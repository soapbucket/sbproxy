//! The `owasp_api_top10` pseudo-policy: parse, validate, and expand into
//! concrete synthesized policy entries before the module-layer dispatch
//! in `sbproxy-modules::compile.rs` ever sees them (WOR-2491).
//!
//! `owasp_api_top10` is not a real [`crate::snapshot::CompiledOrigin`]
//! policy. It is a directive read and consumed by
//! `expand_owasp_pack`, called from `compiler::compile_origin` before
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
//! in `ITEM_TABLE`. A row's `ItemRow::pieces` list holds zero or
//! more independently-backing-off synthesized policies: `api1` and
//! `api5` synthesize one apiece (sharing a single `object_authz` entry
//! when both are enabled), and `api8` synthesizes two
//! (`security_headers`, `http_framing`). Each piece backs off on its
//! own, so an operator who authors just one of the underlying policy
//! types still gets the pack's coverage for the rest -
//! [`PackManifestEntry::reason`] names exactly which pieces were added
//! and which the operator's own config already covers.
//!
//! `api8`'s `security_headers` piece is additionally
//! `response_phase_gated` (WOR-2491 review round, M1): it only takes
//! effect in Pingora's response-phase filter, which an origin whose
//! action responds entirely inside the request phase (`static`,
//! `mock`, and friends - see `action_runs_response_phase`) never
//! reaches, so it is not synthesized there and the gap is named in the
//! reason instead of claimed. `http_framing` runs at request phase
//! unconditionally and stays ungated.
//!
//! `api7` has an empty `pieces` list but is not `NotCovered`: its
//! control (the proxy's outbound SSRF guard) already runs
//! unconditionally outside the policy chain, so
//! `ItemRow::already_enforced_reason` reports
//! [`PackItemState::Enforced`] with nothing added to `policies` - the
//! reason is explicit that this covers only sbproxy's own outbound
//! dials, not the backend application's own server-side URL fetching
//! (the API7:2023 risk as OWASP defines it), which this pack cannot
//! see. `api2`, `api6`, and `api10` report [`PackItemState::NotCovered`]
//! with a reason naming the gap; no synthesis is wired for them in
//! this pack version.
//!
//! `api1`'s and `api5`'s shared `object_authz` entry always reports
//! [`PackItemState::NeedsOperatorInput`] regardless of posture: with
//! `object_rules` and `function_rules` both empty, neither BOLA
//! ownership checking nor BFLA role checking has anything to evaluate.
//! The enumeration sub-check is the exception: with `object_rules`
//! empty, `ObjectAuthzPolicy::decide` falls back to a ruleless
//! path-shape heuristic for identified callers and reports id sweeps
//! as detect-only violations (audited and counted, never blocked; see
//! `synth_object_authz`'s doc comment). The state names what is still
//! missing - the ownership rules only an operator can author - not
//! whether that audit-only fallback is running, which it is.
//!
//! `api3` and `api9` do not fit the `ItemRow`/`SynthPiece` table shape
//! at all, so `expand_owasp_pack` special-cases both before it ever
//! consults `ITEM_TABLE` for them (their table rows exist only so
//! every [`PackItem`] variant still has one, per that invariant, and
//! are marked unused in their own fields):
//!
//! - `api3` (`expand_api3_entry`) splits into a request half that
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
//! - `api9` (`expand_api9_entry`) sets the origin-level
//!   `expose_openapi` boolean (`RawOriginConfig::expose_openapi`,
//!   confirmed origin-scoped at `types.rs:7580-7585`, not
//!   server-level) directly, since that field is not a `type:` entry
//!   in either list this pack otherwise touches.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// One of the ten OWASP API Security Top 10 (2023) risk items this pack
/// can address. Every variant has a row in `ITEM_TABLE`, even when
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
    /// Every item, in ascending OWASP numbering order. `expand_owasp_pack`
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
    /// `synth_object_authz`) without changing this field; this is
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
///
/// `deny_unknown_fields` (WOR-2491 review round, M4): a typo like
/// `per_items:` (plural) for `per_item:` used to deserialize
/// silently, since serde drops unrecognized keys by default - an
/// operator who made that typo believed their overrides took effect
/// and they were dropped instead. Declaring `deny_unknown_fields`
/// means every real key must be named on this struct, including
/// `type` itself (`_pack_type` below): the caller already matched on
/// it to find this entry before deserializing, so nothing reads the
/// field again, but leaving it undeclared would make the entry's own
/// discriminator an "unknown field" and refuse every pack config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackConfig {
    /// The `type: owasp_api_top10` discriminator. See the struct doc
    /// comment for why this is declared at all.
    #[serde(rename = "type")]
    _pack_type: String,
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
    /// `expand_api3_entry`). Rejected on any other item; rejected if
    /// present but empty (omit the key instead - an empty list is not
    /// the same request as "strip nothing").
    #[serde(default)]
    response_exclude_fields: Option<Vec<String>>,
    /// `api4`-only: requests-per-second budget for the pack's
    /// `rate_limiting` and `ddos_protection` pieces (see
    /// [`expand_api4_entry`]). Rejected on any other item; rejected if
    /// present but not a positive number. Both pieces key by the
    /// caller's observed IP by default, and behind a load balancer
    /// with no `proxy.trusted_proxies` configured every real client
    /// collapses to the LB's one IP and shares a single budget - this
    /// pack refuses to guess a number rather than risk that outage
    /// class (WOR-2491 review round, B1).
    #[serde(default)]
    rps: Option<f64>,
}

/// Returns true when the JSON value's `type` field equals `wanted`.
///
/// A local copy of `compiler::config_type_is`: small enough that
/// sharing it across the module boundary is not worth the coupling.
fn config_type_is(value: &serde_json::Value, wanted: &str) -> bool {
    value.get("type").and_then(|v| v.as_str()) == Some(wanted)
}

/// Appends `entry` to `transforms`, unless a `json_envelope` entry is
/// already present, in which case `entry` is inserted immediately
/// before the *first* one instead.
///
/// WOR-2491 review round (json_envelope ordering interaction):
/// `compiler::compile_origin` auto-wires a `json_envelope` transform
/// at the end of the default content-shaping chain
/// (`boilerplate -> html_to_markdown -> citation_block ->
/// json_envelope`) whenever the origin authors `ai_crawl_control` (or
/// a Wave 4 content-shaping transform) with an empty `transforms:`
/// list, and that auto-wire runs before this pack's own expansion.
/// `json_envelope` wraps the response body into an envelope object
/// (`{"content": ..., ...}`); `api3`'s synthesized `json_projection`
/// only filters *top-level* object keys (see `expand_api3_entry`'s
/// doc comment), so appending it after `json_envelope` would filter
/// the envelope's own keys instead of the real data nested under
/// `content`. Inserting ahead of `json_envelope` keeps the projection
/// looking at the actual response shape.
fn insert_transform_before_json_envelope(
    transforms: &mut Vec<serde_json::Value>,
    entry: serde_json::Value,
) {
    match transforms
        .iter()
        .position(|t| config_type_is(t, "json_envelope"))
    {
        Some(idx) => transforms.insert(idx, entry),
        None => transforms.push(entry),
    }
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

/// One independently-backing-off policy inside an `ItemRow`. Most
/// items have exactly one piece; `api8` has two, so an operator who
/// authors just one of the underlying policy types still gets the
/// pack's coverage for the rest, with the manifest reason naming
/// exactly which pieces backed off and which the pack added. `api1`
/// and `api5` each have exactly one piece too, but both point at
/// `object_authz`/`bola`: enabling both together produces one shared
/// entry, not two (see `shared_backoff_reason`). `api4`'s four pieces
/// no longer go through this table at all (see
/// [`expand_api4_entry`]): two need an operator-supplied budget this
/// table's `fn(PackPosture) -> PieceSynthesis` signature cannot carry.
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
    /// True when this piece's policy only takes effect during
    /// response-phase processing (WOR-2491 review round, M1): today
    /// only `api8`'s `security_headers` piece. See
    /// `action_runs_response_phase` for which action types reach
    /// that phase; every other piece leaves this `false`.
    response_phase_gated: bool,
    /// Synthesizes this one policy entry.
    synth: fn(PackPosture) -> PieceSynthesis,
}

/// True when an origin whose action has this `type:` string reaches
/// Pingora's response-phase filter (`server/proxy_http.rs::response_filter`),
/// where `api8`'s `security_headers` piece takes effect.
///
/// The principle (WOR-2491 review round): this asks whether the
/// action's *normal, successful* traffic reaches `response_filter`,
/// not whether every possible code path for that action type does.
/// Verified against `action_dispatch.rs::handle_action`'s own match:
///
/// - `Action::Proxy`, `Action::LoadBalancer`, `Action::WebSocket`, and
///   `Action::A2a` always return `Ok(false)` (fall through to
///   `upstream_peer`/`response_filter`).
/// - `Action::GraphQL` and `Action::Grpc` also return `Ok(false)` for
///   their normal path. Both have early `Ok(true)` returns, but only
///   on request-validation failure - GraphQL's body-too-large (413)
///   or replay-capture failure (400), Grpc's unmatched-transcode-route
///   (404) - the same shape every action's own error handling takes;
///   an ordinary, valid request for either always reaches
///   `response_filter`, so both belong in this allowlist.
/// - `Action::AiProxy` does not, and this is the genuine asymmetry
///   with GraphQL/Grpc above: its normal, successful path calls
///   `handle_ai_proxy(...).await?; Ok(true)` unconditionally - every
///   ordinary AI proxy request (not just error cases) is answered
///   entirely inside `request_filter` and never reaches
///   `response_filter` at all. Only a narrow realtime-WebSocket-upgrade
///   sub-case returns `Ok(false)`. Since a compile-time decision
///   cannot see which sub-path a given request will take, `ai_proxy`
///   is treated as not-guaranteed here rather than claiming coverage
///   most requests will not get.
/// - Every other action type (`static`, `redirect`, `echo`, `mock`,
///   `beacon`, `noop`, `mcp`, `storage`, any plugin action, or an
///   unrecognized string) responds from inside `request_filter`
///   unconditionally and never reaches `response_filter`.
///
/// `action_runs_response_phase_matches_the_verified_action_set` (this
/// module's own tests) pins the exact allowlist against a hardcoded
/// expectations list; a future edit to `handle_action`'s match arms
/// that changes which actions short-circuit must also touch that test,
/// so drift is a conscious two-place edit rather than a silent one.
fn action_runs_response_phase(action_type: &str) -> bool {
    matches!(
        action_type,
        "proxy" | "load_balancer" | "websocket" | "a2a" | "graphql" | "grpc"
    )
}

/// One row of the per-item expansion table.
///
/// `pieces` is empty for items with no synthesis target at all.
/// `ItemRow::already_enforced_reason` distinguishes "genuinely
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
    /// defaults are safe to block blind (`api8`);
    /// [`PackItemState::NeedsOperatorInput`] for items whose synthesis
    /// still needs operator-authored rules regardless of posture
    /// (`api1`, `api5`). Unused when `pieces` is empty (which includes
    /// `api4`'s row - see [`expand_api4_entry`], which computes its
    /// own state instead of reading this field).
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
/// The enumeration flag does two things. Today, with `object_rules`
/// empty, `ObjectAuthzPolicy::decide`
/// (`sbproxy-modules::policy::object_authz`) falls back to its ruleless
/// path-shape heuristic (`heuristic_object_key`) for callers with a
/// resolved `principal.owner`: an identified caller sweeping more than
/// `enumeration.max_distinct` distinct path-shaped ids inside the
/// window produces a detect-only violation - a
/// `sbproxy_object_authz_violations_total{kind="enumeration"}`
/// increment and a security-audit record, never a block, regardless of
/// posture. And the moment an operator adds an `object_rules` entry
/// with an `object_param`, enumeration narrows to rule-captured ids
/// and its violations follow `test_mode` like any other. What the pack
/// still cannot synthesize is BOLA ownership coverage: an
/// `object_rules` entry needs the operator's own path template and
/// owner mapping, which no default can infer.
fn synth_object_authz(posture: PackPosture) -> PieceSynthesis {
    let test_mode = matches!(posture, PackPosture::ReportOnly);
    let policy = serde_json::json!({
        "type": "object_authz",
        "test_mode": test_mode,
        "enumeration": { "enabled": true },
    });
    let mode_note = if test_mode {
        "test_mode: true, so a rule-derived violation is audited but the request passes"
    } else {
        "test_mode: false, so a rule-derived violation is blocked"
    };
    PieceSynthesis {
        policy,
        synthesized_type: "object_authz",
        reason: format!(
            "synthesized object_authz with empty object_rules and enumeration.enabled: true \
             ({mode_note}). With object_rules empty the ruleless path-shape heuristic is \
             active: an identified caller sweeping many distinct ids is reported as an \
             enumeration violation for audit only (counted and logged, never blocked, \
             regardless of posture). Real BOLA ownership coverage still needs an \
             operator-authored object_rules entry, which this pack cannot infer; adding one \
             scopes enumeration to rule-captured ids and makes violations follow test_mode."
        ),
    }
}

/// Synthesizes `api5`'s own `object_authz` entry for the case where
/// `api5` is enabled without `api1` (so there is no shared entry to
/// join). `function_rules` is explicitly empty: real BFLA coverage
/// needs an operator-authored rule naming the privileged path, method
/// set, and required role, which this pack cannot infer. `posture`
/// threads into `test_mode` for consistency with `synth_object_authz`,
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
                  adding a second; the shared entry then also carries api1's ruleless \
                  enumeration heuristic, which reports id sweeps for audit only."
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
/// any configured limit); it also has no caller-identity knob at all
/// (the check is on the request's own shape, not who sent it), so
/// unlike `rate_limiting`/`ddos_protection` below it is safe to
/// synthesize unconditionally regardless of `proxy.trusted_proxies`
/// (WOR-2491 review round, B1).
fn synth_request_limit() -> PieceSynthesis {
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
                  virtually any JSON API and independent of caller identity, so it is safe to \
                  default blind regardless of proxy.trusted_proxies."
            .to_string(),
    }
}

/// `burst` for [`synth_rate_limiting`]'s token bucket at a given
/// `rps` budget: twice the per-second rate, the same ratio the pack's
/// old fixed default used (100 rps / 200 burst). This is the ceiling
/// of what `rate_limiting` itself tolerates before throttling; a
/// client bursting up to this many requests is within budget as far
/// as `rate_limiting` is concerned; see [`ddos_threshold_from_burst`]
/// for why `synth_ddos_protection` must not block inside it.
fn rate_limit_burst_from_rps(rps: f64) -> u64 {
    (rps * 2.0).round().max(1.0) as u64
}

/// `api4`'s `ddos_protection` per-second threshold, derived from
/// [`rate_limit_burst_from_rps`]'s `burst` rather than from `rps`
/// directly (WOR-2491 review round: a real interaction bug caught in
/// review). `ddos.rs::check` hard-blocks an IP for `block_duration_secs`
/// (five minutes at the module default) the moment its count inside
/// the current 1-second window exceeds the threshold - there is no
/// throttle-first step the way `rate_limiting`'s token bucket has.
/// Setting the threshold to `rps` itself (the original shape of this
/// function) meant a client legitimately bursting between `rps` and
/// `burst` requests - squarely inside what `rate_limiting`'s own
/// advertised tolerance allows - tripped a five-minute IP block
/// instead of an ordinary 429. The threshold must clear the burst
/// ceiling with headroom, so `ddos_protection` only fires meaningfully
/// *above* what `rate_limiting` already tolerates, not inside it:
/// `ceil(burst * 1.5)`, always strictly greater than `burst` for any
/// `burst >= 1`.
fn ddos_threshold_from_burst(burst: u64) -> u64 {
    ((burst as f64) * 1.5).ceil() as u64
}

/// Synthesizes `api4`'s `rate_limiting` piece at an operator-supplied
/// budget: a per-caller token bucket meant to catch a runaway or
/// scripted client rather than constrain normal traffic. With no
/// `key` expression configured, the enforcer buckets per caller
/// (client IP) by default. `burst` is [`rate_limit_burst_from_rps`].
///
/// `rps` is never guessed (WOR-2491 review round, B1): this piece and
/// [`synth_ddos_protection`] both key on the caller's *observed* IP
/// by default, and behind a load balancer with no
/// `proxy.trusted_proxies` configured every real client collapses to
/// the LB's one IP, sharing a single budget - a fixed blind default
/// here would produce exactly that outage class the moment real
/// traffic exceeded it. The caller (`expand_api4_entry`) only invokes
/// this once `per_item.api4.rps` is confirmed present.
fn synth_rate_limiting(rps: f64) -> PieceSynthesis {
    let burst = rate_limit_burst_from_rps(rps);
    let policy = serde_json::json!({
        "type": "rate_limiting",
        "requests_per_second": rps,
        "burst": burst,
    });
    PieceSynthesis {
        policy,
        synthesized_type: "rate_limiting",
        reason: format!(
            "synthesized rate_limiting at the operator-supplied per_item.api4.rps budget \
             (requests_per_second: {rps}, burst: {burst}), per-caller by default since no key \
             is set. rate_limiting has no report-only mode; posture has no effect on this \
             piece."
        ),
    }
}

/// Synthesizes `api4`'s `concurrent_limit` piece: a shared in-flight
/// budget for the whole origin (`key_by` left unset, which
/// `ConcurrentLimitPolicy::from_config` defaults to `"global"` - one
/// counter for the policy mount, confirmed at `concurrent_limit.rs`).
/// This backstops a stalled or slow upstream piling up requests, a
/// different failure mode than the per-caller rate limit above.
/// `concurrent_limit` has no report-only knob, so `posture` has no
/// effect on this piece. `key_by: global` does not key on caller
/// identity at all (every request through this origin shares the one
/// counter), so unlike `rate_limiting`/`ddos_protection` it is not
/// exposed to the `trusted_proxies` outage class and stays safe to
/// synthesize unconditionally (WOR-2491 review round, B1).
fn synth_concurrent_limit() -> PieceSynthesis {
    let policy = serde_json::json!({
        "type": "concurrent_limit",
        "max": 200,
    });
    PieceSynthesis {
        policy,
        synthesized_type: "concurrent_limit",
        reason: "synthesized concurrent_limit (max: 200, key_by left unset so it defaults to \
                  global: one shared in-flight budget for the whole origin, not keyed on \
                  caller identity): a backstop against a stalled or slow upstream piling up \
                  requests. concurrent_limit has no report-only mode; posture has no effect on \
                  this piece."
            .to_string(),
    }
}

/// Synthesizes `api4`'s `ddos_protection` piece at an operator-supplied
/// budget: `requests_per_second` set to [`ddos_threshold_from_burst`]
/// of the *same* `burst` [`synth_rate_limiting`] computes for this
/// `rps` (not `rps` itself - see that function's doc comment for the
/// real bug this fixes), everything else (`block_duration_secs`, the
/// sliding-window width) left at `ddos.rs`'s own module defaults
/// (300-second block) per the review ruling - only the rate axis is
/// operator-controlled here.
///
/// `rps` is never guessed, for the same reason [`synth_rate_limiting`]
/// documents: this piece keys on the caller's observed IP, and behind
/// a load balancer with no `proxy.trusted_proxies` configured every
/// real client collapses to the LB's one IP (WOR-2491 review round,
/// B1).
fn synth_ddos_protection(rps: f64) -> PieceSynthesis {
    let burst = rate_limit_burst_from_rps(rps);
    let requests_per_second = ddos_threshold_from_burst(burst);
    let policy = serde_json::json!({
        "type": "ddos_protection",
        "requests_per_second": requests_per_second,
    });
    PieceSynthesis {
        policy,
        synthesized_type: "ddos_protection",
        reason: format!(
            "synthesized ddos_protection at requests_per_second: {requests_per_second} - \
             headroom above rate_limiting's own burst ceiling ({burst}) for this rps budget, \
             not the raw per_item.api4.rps value itself, so a client bursting within \
             rate_limiting's advertised tolerance is throttled there instead of tripping a \
             five-minute IP block here. block_duration_secs stays at ddos.rs's own module \
             default (300-second block, sliding 1-second window). ddos_protection has no \
             report-only mode; posture has no effect on this piece."
        ),
    }
}

/// Builds `api4`'s manifest entry. Does not use the `SynthPiece` table
/// (see the `ITEM_TABLE` row's own doc comment): two of its four
/// pieces (`rate_limiting`, `ddos_protection`) need an
/// operator-supplied `per_item.api4.rps` budget before they can
/// synthesize anything, which `SynthPiece::synth: fn(PackPosture) ->
/// PieceSynthesis` has no parameter for.
///
/// `request_limit` and `concurrent_limit` are unconditional and safe
/// to default blind (see their own doc comments: neither keys on
/// caller identity). `rate_limiting` and `ddos_protection` back off
/// to the operator's own policy when authored, synthesize at `rps`
/// when supplied, and otherwise are simply not synthesized - this is
/// the review ruling (WOR-2491, B1) that replaced the pack's original
/// fixed defaults (100 rps for both) after those defaults were found
/// to reproduce an outage class: both key on the caller's observed IP
/// by default, and behind a load balancer with no
/// `proxy.trusted_proxies` configured every real client collapses to
/// the LB's single IP, sharing (and quickly exhausting) one budget.
///
/// Overall state is [`PackItemState::NeedsOperatorInput`] whenever
/// either rate-shaped piece has a gap (absent and not
/// operator-authored) - the state names what is missing (the budget,
/// and the `trusted_proxies` prerequisite for it to mean anything),
/// not whether `request_limit`/`concurrent_limit` are already
/// covering part of this item, mirroring `api1`'s established
/// precedent. Otherwise [`PackItemState::Enforced`].
fn expand_api4_entry(
    operator_authored_types: &HashSet<String>,
    rps: Option<f64>,
    policies: &mut Vec<serde_json::Value>,
) -> PackManifestEntry {
    let mut synthesized_types = Vec::new();
    let mut fragments: Vec<String> = Vec::new();
    let mut has_rate_gap = false;

    if operator_authored_types.contains("request_limit")
        || operator_authored_types.contains("request_limiting")
    {
        fragments.push(
            "request_limit: origin already authors a request_limit/request_limiting policy; \
             the pack leaves it exactly as configured."
                .to_string(),
        );
    } else {
        let synthesis = synth_request_limit();
        policies.push(synthesis.policy);
        synthesized_types.push(synthesis.synthesized_type);
        fragments.push(synthesis.reason);
    }

    if operator_authored_types.contains("concurrent_limit")
        || operator_authored_types.contains("concurrent_limiting")
    {
        fragments.push(
            "concurrent_limit: origin already authors a concurrent_limit/concurrent_limiting \
             policy; the pack leaves it exactly as configured."
                .to_string(),
        );
    } else {
        let synthesis = synth_concurrent_limit();
        policies.push(synthesis.policy);
        synthesized_types.push(synthesis.synthesized_type);
        fragments.push(synthesis.reason);
    }

    let rate_gap_reason = || {
        "NOT synthesized: rate_limiting and ddos_protection both key on the caller's observed \
         IP by default, and behind a load balancer with no proxy.trusted_proxies configured \
         every real client collapses to the load balancer's single IP, sharing (and quickly \
         exhausting) one budget - the exact outage class a blind default here would risk. Set \
         per_item.api4.rps to an operator-chosen requests-per-second budget once \
         proxy.trusted_proxies covers the load balancer's address (or this origin has no load \
         balancer in front of it), and both pieces synthesize at that budget."
    };

    if operator_authored_types.contains("rate_limiting") {
        fragments.push(
            "rate_limiting: origin already authors a rate_limiting policy; the pack leaves it \
             exactly as configured."
                .to_string(),
        );
    } else if let Some(rps_value) = rps {
        let synthesis = synth_rate_limiting(rps_value);
        policies.push(synthesis.policy);
        synthesized_types.push(synthesis.synthesized_type);
        fragments.push(synthesis.reason);
    } else {
        has_rate_gap = true;
        fragments.push(format!("rate_limiting: {}", rate_gap_reason()));
    }

    if operator_authored_types.contains("ddos")
        || operator_authored_types.contains("ddos_protection")
    {
        fragments.push(
            "ddos_protection: origin already authors a ddos/ddos_protection policy; the pack \
             leaves it exactly as configured."
                .to_string(),
        );
    } else if let Some(rps_value) = rps {
        let synthesis = synth_ddos_protection(rps_value);
        policies.push(synthesis.policy);
        synthesized_types.push(synthesis.synthesized_type);
        fragments.push(synthesis.reason);
    } else {
        has_rate_gap = true;
        fragments.push(format!("ddos_protection: {}", rate_gap_reason()));
    }

    // Precedence: a rate-shaped gap always dominates (the state names
    // what is missing, mirroring api1's established precedent) even
    // when request_limit/concurrent_limit did synthesize; only when
    // there is no gap AND nothing at all was added does this collapse
    // to OperatorAuthored (all four pieces were the operator's own),
    // matching every other item's "the pack added nothing" outcome.
    let state = if has_rate_gap {
        PackItemState::NeedsOperatorInput
    } else if synthesized_types.is_empty() {
        PackItemState::OperatorAuthored
    } else {
        PackItemState::Enforced
    };

    PackManifestEntry {
        item: PackItem::Api4,
        state,
        reason: fragments.join(" "),
        synthesized_types,
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
///
/// Two things this half does NOT cover, named explicitly rather than
/// implied by the general claim (WOR-2491 review round, B2):
///
/// - `JsonProjectionTransform::apply` (`transform/json.rs`) filters
///   **top-level object keys only**: a JSON array response body, or
///   an object whose sensitive fields sit inside a nested object or
///   array, passes through unchanged. The reason and every doc
///   surface say "top-level object JSON response bodies", never
///   "every JSON response body".
/// - the synthesized entry sets `"failure_posture": "closed"`
///   (`TransformConfig::failure_posture`, a sibling of `type` at the
///   transform-wrapper level, not a `json_projection`-local field):
///   without it the wrapper's own default is `open`, meaning an
///   oversized or unparseable body - both attacker-influenceable -
///   ships raw instead of filtered, leaking exactly the fields this
///   piece exists to strip. `closed` makes the pipeline refuse the
///   response instead (`server/proxy_http.rs`'s pre-capture size
///   refusal, and `action_dispatch.rs`'s plugin-action path, both key
///   off this same field).
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
                "failure_posture": "closed",
            });
            insert_transform_before_json_envelope(transforms, policy);
            synthesized_types.push("json_projection");
            (
                format!(
                    "response side: synthesized json_projection (fields: [{}], exclude: true, \
                     failure_posture: closed) onto the origin's transform chain, stripping \
                     these fields from the top level of every JSON *object* response body via \
                     response_body_filter - a JSON array body, or a sensitive field nested \
                     inside an object or array rather than at the top level, passes through \
                     unchanged; scope this to responses whose sensitive fields are top-level. \
                     failure_posture: closed means an oversized or unparseable body is refused \
                     rather than shipped raw and unfiltered. json_projection has no \
                     report-only mode; posture has no effect on this half.",
                    fields.join(", ")
                ),
                true,
            )
        }
        None => (
            "response side: no per_item.api3.response_exclude_fields supplied, so nothing was \
             synthesized. sbproxy-modules::transform::json::JsonProjectionTransform (config \
             type json_projection) already strips named fields from the top level of buffered \
             JSON object response bodies via response_body_filter (a JSON array body, or a \
             field nested inside an object or array, is out of scope for this transform \
             regardless), but needs an operator-supplied field list this pack cannot infer. Set \
             per_item.api3.response_exclude_fields: [field, ...] to enable it."
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

/// The `api1` piece: shared with `api5`, see `synth_object_authz`.
const API1_PIECES: [SynthPiece; 1] = [SynthPiece {
    backoff_types: &["object_authz", "bola"],
    operator_backoff_reason: "origin already authors an object_authz/bola policy; the pack \
                               leaves it exactly as configured, including its own posture",
    shared_backoff_reason: None,
    response_phase_gated: false,
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
    response_phase_gated: false,
    synth: synth_object_authz_bfla_only,
}];

/// `api8`'s two independently-backing-off pieces. A managed `waf`
/// (Core Rule Set) default is intentionally not part of this row: the
/// task brief scopes `api8` to `security_headers` and `http_framing`
/// only. `waf`'s own `test_mode` knob (`waf/policy.rs`) makes it a
/// reasonable candidate for a future version of this pack (matching
/// the research sketch), but adding it is deferred rather than folded
/// in here. Configure `waf` directly for CRS-based coverage today.
///
/// `security_headers` is `response_phase_gated: true` (WOR-2491
/// review round, M1): it only takes effect in Pingora's response
/// filter, so it is not synthesized on an origin whose action never
/// reaches that filter (see `action_runs_response_phase`).
/// `http_framing` runs at request phase instead, via the
/// `check_policies` enforcer registry every origin goes through
/// before any action dispatch decision, independent of action type -
/// confirmed at `server/request_phase.rs`'s own `check_policies`
/// call site - so it stays ungated.
const API8_PIECES: [SynthPiece; 2] = [
    SynthPiece {
        backoff_types: &["security_headers"],
        operator_backoff_reason: "origin already authors a security_headers policy; the pack \
                                   leaves it exactly as configured",
        shared_backoff_reason: None,
        response_phase_gated: true,
        synth: synth_security_headers,
    },
    SynthPiece {
        backoff_types: &["http_framing"],
        operator_backoff_reason: "origin already authors an http_framing policy; the pack \
                                   leaves it exactly as configured",
        shared_backoff_reason: None,
        response_phase_gated: false,
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
        // Unused: `expand_owasp_pack`'s main loop special-cases api4
        // via `expand_api4_entry` before it ever calls `item_row` for
        // this variant (the `rate_limiting`/`ddos_protection` pieces
        // are gated on `per_item.api4.rps`, which the generic
        // `SynthPiece::synth: fn(PackPosture) -> PieceSynthesis`
        // signature has no way to receive - WOR-2491 review round,
        // B1). This row exists only so every `PackItem` variant still
        // has exactly one entry, per `item_row`'s own doc comment.
        item: PackItem::Api4,
        pieces: &[],
        covered_state: PackItemState::NotCovered,
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
             broad; this pack does not compute that check from here. This covers only sbproxy's \
             own outbound dials - the ones this gateway itself makes on the proxy process's \
             behalf. It does NOT cover the backend application's own server-side URL fetching \
             (the API7:2023 risk as OWASP defines it: a caller supplies a URL, or a value the \
             app resolves into one, and the app's own code fetches it), which happens entirely \
             behind this origin's action and this pack cannot see or guard.",
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
/// one row in `ITEM_TABLE`, so this only returns `None` if a future
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
/// downstream: `expand_owasp_pack` walks [`PackItem::ALL`] order).
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
/// it was not already (see `expand_api9_entry`).
///
/// `action_type` is the origin's action's own `type:` string (`""`
/// when absent or not yet known, which resolves the same as any other
/// unrecognized string: no response-phase piece is synthesized). Used
/// only by `api8`'s `security_headers` piece (WOR-2491 review round,
/// M1): that policy takes effect in Pingora's response-phase filter,
/// which only runs for actions that dial a real upstream peer, so an
/// action handled entirely in the request phase (`static`, `mock`,
/// and friends) gets the reason named instead of a claim nothing
/// enforces. See `action_runs_response_phase`.
///
/// Returns `Ok(None)` when the origin has no `owasp_api_top10` entry -
/// `transforms` and `*expose_openapi` are left untouched in that case.
/// Returns `Err` for: more than one `owasp_api_top10` entry on the
/// origin, an unknown item name in `enable` or `per_item`, a duplicate
/// item name within `enable`, a `per_item` override for an item not
/// named in `enable`, a `response_exclude_fields` override on any item
/// other than `api3`, an empty `response_exclude_fields` list, an
/// `api4.rps` override on any item other than `api4`, an `api4.rps`
/// that is not a positive number, or a malformed `posture`/`enable`
/// value.
///
/// `pub(crate)`: every caller (`compiler::compile_origin`,
/// `validate::check_owasp_pack_config`, `plan::owasp_pack_preview`)
/// lives inside this crate, so this expansion step does not need to
/// be reachable outside `sbproxy-config`.
pub(crate) fn expand_owasp_pack(
    hostname: &str,
    policies: &mut Vec<serde_json::Value>,
    transforms: &mut Vec<serde_json::Value>,
    expose_openapi: &mut bool,
    action_type: &str,
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
    let mut api4_rps: Option<f64> = None;
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
        if let Some(rps) = entry.rps {
            if item != PackItem::Api4 {
                anyhow::bail!(
                    "origin '{hostname}': owasp_api_top10 per_item.{key}.rps is only valid for \
                     api4; {} does not accept it",
                    item.canonical_name()
                );
            }
            // Not `!(rps > 0.0)` (clippy::neg_cmp_op_on_partial_ord):
            // that form and this one differ on NaN, and NaN must stay
            // refused. `rps > 0.0` is `false` for NaN, so the negated
            // form refuses it (correct); `rps <= 0.0` is ALSO `false`
            // for NaN (`PartialOrd`, not `Ord` - NaN compares
            // unordered against everything), so it would let NaN
            // through unrefused. `!rps.is_finite() || rps <= 0.0`
            // refuses NaN and infinities explicitly, then refuses
            // non-positive finite values with a plain `<=`.
            if !rps.is_finite() || rps <= 0.0 {
                anyhow::bail!(
                    "origin '{hostname}': owasp_api_top10 per_item.api4.rps must be a positive \
                     number; got {rps}"
                );
            }
            api4_rps = Some(rps);
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

        // api3, api4, and api9 do not fit the ItemRow/SynthPiece table
        // (see each function's doc comment): resolve them directly
        // and skip the generic per-row machinery below entirely.
        if item == PackItem::Api3 {
            entries.push(expand_api3_entry(
                &operator_authored_types,
                api3_response_exclude_fields.as_deref(),
                transforms,
            ));
            continue;
        }
        if item == PackItem::Api4 {
            entries.push(expand_api4_entry(
                &operator_authored_types,
                api4_rps,
                policies,
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
        let mut any_phase_gapped = false;

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
            // WOR-2491 review round, M1: a response-phase-only piece
            // (api8's security_headers) is not synthesized on an
            // origin whose action never reaches Pingora's
            // response-phase filter. Checked before the shared/synth
            // branches below: an action that skips response-phase
            // enforcement skips it regardless of what an earlier item
            // in this same pass already synthesized.
            if piece.response_phase_gated && !action_runs_response_phase(action_type) {
                any_phase_gapped = true;
                fragments.push(format!(
                    "{} is response-phase only (it takes effect in Pingora's response filter) \
                     and this origin's action ('{}') never reaches that filter: only proxy, \
                     load_balancer, websocket, a2a, graphql, and grpc actions do. Not \
                     synthesized here; configure it directly on the app behind this origin, or \
                     move this route to a proxy/load_balancer action.",
                    piece
                        .backoff_types
                        .first()
                        .copied()
                        .unwrap_or("this policy"),
                    if action_type.is_empty() {
                        "(none)"
                    } else {
                        action_type
                    }
                ));
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
        } else if any_phase_gapped {
            // Nothing was added and it is not because the operator
            // already authored it: this origin's action type cannot
            // run the piece at all. Not `OperatorAuthored` (the
            // operator did nothing) and not the row's usual
            // `covered_state` (nothing here is actually covered).
            PackItemState::NotCovered
        } else {
            debug_assert!(
                any_operator_backoff,
                "a non-empty pieces list must either synthesize/share, back off, or phase-gap"
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
            .expect("expand");
        assert!(manifest.is_none());
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn a_typo_d_per_items_field_is_refused_naming_the_field() {
        // WOR-2491 review round, M4: before `deny_unknown_fields`,
        // `per_items` (plural, a typo for `per_item`) deserialized
        // silently - the operator's overrides were dropped without
        // any error. `RawPackConfig` now refuses it, naming the field.
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "per_items": {"api1": {"posture": "enforce"}},
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
            .unwrap_err()
            .to_string();
        assert!(err.contains("per_items"), "names the bad field: {err}");
    }

    #[test]
    fn unknown_item_name_in_enable_is_refused_with_accepted_list() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1", "api99"],
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
            .expect("expand");
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api1).expect("api1 entry");
        // Ruling (plan ledger): api1's state is always
        // needs_operator_input, not enforced/report_only, since empty
        // object_rules means no real ownership check runs either way.
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);
        assert_eq!(entry.synthesized_types, vec!["object_authz"]);
        // The manifest reason must describe the ruleless enumeration
        // heuristic as live and audit-only (#1118/#1128), not claim
        // the entry flags nothing.
        assert!(
            entry.reason.contains("ruleless path-shape heuristic"),
            "reason must name the live audit-only heuristic: {}",
            entry.reason
        );
        assert!(
            !entry.reason.contains("does not yet block or flag anything"),
            "stale pre-#1118 claim resurfaced: {}",
            entry.reason
        );

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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
    fn back_off_also_recognizes_the_bola_alias() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api1"]}),
            serde_json::json!({"type": "bola", "object_rules": []}),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
    fn api4_needs_operator_input_and_synthesizes_only_the_safe_pieces_when_no_rps_given() {
        // WOR-2491 review round, B1: rate_limiting and ddos_protection
        // both key on the caller's observed IP by default, so they
        // are no longer synthesized blind. request_limit and
        // concurrent_limit are not IP-keyed and still synthesize
        // unconditionally.
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api4"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api4).expect("api4 entry");
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);
        let mut types = entry.synthesized_types.clone();
        types.sort_unstable();
        assert_eq!(
            types,
            vec!["concurrent_limit", "request_limit"],
            "rate_limiting and ddos_protection are not synthesized without per_item.api4.rps"
        );
        assert!(
            entry.reason.contains("per_item.api4.rps"),
            "the reason names the missing budget: {}",
            entry.reason
        );
        assert!(
            entry.reason.contains("trusted_proxies"),
            "the reason names the trusted_proxies prerequisite: {}",
            entry.reason
        );
        assert!(
            !policies.iter().any(|p| config_type_is(p, "rate_limiting")),
            "no rate_limiting synthesized"
        );
        assert!(
            !policies
                .iter()
                .any(|p| config_type_is(p, "ddos_protection")),
            "no ddos_protection synthesized"
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

        let concurrent_limit = policies
            .iter()
            .find(|p| config_type_is(p, "concurrent_limit"))
            .expect("concurrent_limit present");
        assert_eq!(
            concurrent_limit.get("max").and_then(|v| v.as_u64()),
            Some(200)
        );
    }

    #[test]
    fn api4_enforced_and_synthesizes_all_four_pieces_when_rps_given() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api4"],
            "per_item": {"api4": {"rps": 50.0}},
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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

        let rate_limiting = policies
            .iter()
            .find(|p| config_type_is(p, "rate_limiting"))
            .expect("rate_limiting present");
        assert_eq!(
            rate_limiting
                .get("requests_per_second")
                .and_then(|v| v.as_f64()),
            Some(50.0)
        );
        assert_eq!(
            rate_limiting.get("burst").and_then(|v| v.as_u64()),
            Some(100),
            "burst is twice the supplied rps"
        );

        let ddos = policies
            .iter()
            .find(|p| config_type_is(p, "ddos_protection"))
            .expect("ddos_protection present");
        let ddos_threshold = ddos
            .get("requests_per_second")
            .and_then(|v| v.as_u64())
            .expect("ddos_protection sets an explicit requests_per_second");
        assert_eq!(
            ddos_threshold, 150,
            "ceil(burst * 1.5) = ceil(100 * 1.5) = 150, not the raw rps (50) or burst (100)"
        );
        // WOR-2491 review round: the real bug this fixes. `ddos.rs`
        // hard-blocks for five minutes past its threshold with no
        // throttle-first step; a threshold set to `rps` itself let a
        // client bursting between `rps` and `burst` - squarely inside
        // rate_limiting's own advertised tolerance - trip a
        // five-minute IP block instead of an ordinary 429.
        let burst = rate_limiting
            .get("burst")
            .and_then(|v| v.as_u64())
            .expect("rate_limiting sets an explicit burst");
        assert!(
            ddos_threshold > burst,
            "ddos threshold ({ddos_threshold}) must clear rate_limiting's burst ceiling \
             ({burst}), or a burst inside rate_limiting's own tolerance trips a five-minute \
             block instead of an ordinary 429"
        );
        assert!(
            ddos.get("block_duration_secs").is_none(),
            "block window stays at the module default, per the review ruling"
        );
    }

    #[test]
    fn api4_rejects_a_non_positive_rps() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api4"],
            "per_item": {"api4": {"rps": 0.0}},
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
            .unwrap_err()
            .to_string();
        assert!(err.contains("positive"), "{err}");
    }

    #[test]
    fn rps_refusal_condition_rejects_nan_and_every_non_positive_value() {
        // WOR-2491 review round: pins the exact refusal condition
        // `expand_owasp_pack` uses for `per_item.api4.rps`
        // (`clippy::neg_cmp_op_on_partial_ord`). `!(rps > 0.0)` and
        // `!rps.is_finite() || rps <= 0.0` agree on every ordinary
        // value; they disagree only on NaN, where a bare `rps <= 0.0`
        // would (wrongly) let it through - `PartialOrd`, not `Ord`:
        // NaN compares unordered against everything, including 0.0.
        //
        // Tested directly against `f64` rather than through the JSON
        // pipeline: `serde_json`'s own `f64 -> Value` conversion maps
        // NaN to `Value::Null` (JSON has no NaN representation), which
        // deserializes back to `rps: None` and never reaches this
        // check at all - this is the one place in this pack the
        // condition itself can be exercised.
        let refuses = |rps: f64| !rps.is_finite() || rps <= 0.0;
        assert!(refuses(f64::NAN), "NaN must be refused");
        assert!(refuses(0.0), "zero must be refused");
        assert!(refuses(-5.0), "negative must be refused");
        assert!(refuses(f64::INFINITY), "infinity must be refused");
        assert!(
            refuses(f64::NEG_INFINITY),
            "negative infinity must be refused"
        );
        assert!(
            !refuses(50.0),
            "an ordinary positive value must be accepted"
        );
        assert!(!refuses(0.001), "a small positive value must be accepted");
    }

    #[test]
    fn api4_rejects_rps_on_a_different_item() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "per_item": {"api1": {"rps": 10.0}},
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
            .unwrap_err()
            .to_string();
        assert!(err.contains("only valid for api4"), "{err}");
    }

    #[test]
    fn api4_partial_backoff_when_operator_authors_one_subpolicy() {
        // The operator authors rate_limiting themselves (no gap
        // there) but supplies no per_item.api4.rps, so
        // ddos_protection - gated on the same budget - still gaps:
        // the item as a whole stays NeedsOperatorInput, and the
        // reason must name ddos_protection specifically, not treat
        // the operator's rate_limiting as covering both.
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api4"]}),
            serde_json::json!({"type": "rate_limiting", "requests_per_second": 5.0}),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api4).expect("api4 entry");
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);
        let mut types = entry.synthesized_types.clone();
        types.sort_unstable();
        assert_eq!(
            types,
            vec!["concurrent_limit", "request_limit"],
            "rate_limiting is excluded (operator's own entry stands); ddos_protection is \
             excluded (no per_item.api4.rps)"
        );
        assert!(
            entry.reason.contains("already authors a rate_limiting"),
            "the manifest reason names the partial back-off: {}",
            entry.reason
        );
        assert!(
            entry.reason.contains("ddos_protection"),
            "the manifest reason names ddos_protection's own gap: {}",
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
        assert!(
            !policies
                .iter()
                .any(|p| config_type_is(p, "ddos_protection")),
            "no ddos_protection synthesized"
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        // WOR-2491 review round, M3: the reason must not overclaim -
        // it names sbproxy's own outbound dials, not the backend
        // app's server-side URL fetching (the actual API7:2023 risk).
        assert!(
            entry.reason.contains("does NOT cover"),
            "the reason must name what api7's guard does not cover: {}",
            entry.reason
        );
        assert!(
            entry
                .reason
                .contains("backend application's own server-side URL fetching"),
            "the reason must name the uncovered risk explicitly: {}",
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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

    #[test]
    fn api8_security_headers_not_synthesized_on_a_static_action() {
        // WOR-2491 review round, M1: `static` never reaches Pingora's
        // response-phase filter (`action_dispatch.rs::handle_action`'s
        // own match returns `Ok(true)` unconditionally for it), so
        // security_headers - which only takes effect there - is not
        // synthesized. http_framing runs at request phase regardless
        // of action type and still synthesizes. The item stays
        // Enforced (http_framing is real coverage); the reason names
        // the phase gap explicitly.
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api8"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "static")
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api8).expect("api8 entry");
        assert_eq!(entry.state, PackItemState::Enforced);
        assert_eq!(
            entry.synthesized_types,
            vec!["http_framing"],
            "security_headers is not synthesized on a static action"
        );
        assert!(
            entry.reason.contains("response-phase only"),
            "the reason names the phase gap: {}",
            entry.reason
        );
        assert!(
            entry.reason.contains("'static'"),
            "the reason names the actual action type: {}",
            entry.reason
        );
        assert!(
            !policies
                .iter()
                .any(|p| config_type_is(p, "security_headers")),
            "security_headers must not be synthesized on a static action"
        );
        assert!(
            policies.iter().any(|p| config_type_is(p, "http_framing")),
            "http_framing still synthesizes; it runs at request phase regardless of action type"
        );
    }

    #[test]
    fn api8_security_headers_not_covered_at_all_when_operator_also_authors_http_framing_on_a_static_action(
    ) {
        // Both pieces end up with nothing added by the pack: http_framing
        // because the operator already authors it, security_headers
        // because the action can't run it. Neither is `OperatorAuthored`
        // (the operator did not author security_headers) nor
        // `Enforced` (nothing the pack contributed is actually
        // running); `NotCovered` is the honest label.
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api8"]}),
            serde_json::json!({"type": "http_framing"}),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "mock")
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api8).expect("api8 entry");
        assert_eq!(entry.state, PackItemState::NotCovered);
        assert!(entry.synthesized_types.is_empty());
    }

    #[test]
    fn action_runs_response_phase_matches_the_verified_action_set() {
        // WOR-2491 review round: this hardcoded list is the drift tie
        // against `crates/sbproxy-core/src/server/action_dispatch.rs`'s
        // `handle_action` match. That function decides per action type
        // whether NORMAL (not just any) traffic reaches
        // `Ok(false)`/`response_filter`; `action_runs_response_phase`'s
        // own doc comment records the exact reasoning per type,
        // including why `graphql`/`grpc` (normal path proxies; only
        // request-validation failures short-circuit) are included
        // while `ai_proxy` (normal path never reaches it at all) is
        // not. A future edit to `handle_action`'s match arms that
        // changes which actions short-circuit must update this test
        // too - that is the point of pinning it here rather than only
        // asserting behavior indirectly through a pack test.
        for t in [
            "proxy",
            "load_balancer",
            "websocket",
            "a2a",
            "graphql",
            "grpc",
        ] {
            assert!(action_runs_response_phase(t), "{t}");
        }
        for t in [
            "static",
            "redirect",
            "echo",
            "mock",
            "beacon",
            "noop",
            "mcp",
            "storage",
            "ai_proxy",
            "",
            "some_plugin_action",
        ] {
            assert!(!action_runs_response_phase(t), "{t}");
        }
    }

    // --- WOR-2491 task 3: api3, api9 ---

    #[test]
    fn api3_needs_operator_input_when_nothing_is_configured() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api3"],
        }));
        let mut transforms = Vec::new();
        let manifest = expand_owasp_pack("h", &mut policies, &mut transforms, &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack("h", &mut policies, &mut transforms, &mut false, "proxy")
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
        assert_eq!(
            projection.get("failure_posture").and_then(|v| v.as_str()),
            Some("closed"),
            "WOR-2491 review round, B2: an oversized/unparseable body must be refused, not \
             shipped raw and unfiltered"
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
    fn api3_response_projection_inserts_before_an_existing_json_envelope() {
        // WOR-2491 review round (json_envelope ordering interaction):
        // `json_projection` only filters top-level object keys.
        // json_envelope wraps the body into `{"content": ..., ...}`,
        // so if the projection landed after it, it would filter the
        // envelope's own keys instead of the real data nested under
        // `content`. This is exactly the shape
        // `compiler::compile_origin`'s auto-wired content-shaping
        // chain produces on an `ai_crawl_control` origin with no
        // authored `transforms:`: boilerplate -> html_to_markdown ->
        // citation_block -> json_envelope, added before this pack's
        // own expansion runs.
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api3"],
            "per_item": {
                "api3": {"response_exclude_fields": ["ssn"]},
            },
        }));
        let mut transforms = vec![
            serde_json::json!({"type": "boilerplate"}),
            serde_json::json!({"type": "html_to_markdown"}),
            serde_json::json!({"type": "citation_block"}),
            serde_json::json!({"type": "json_envelope"}),
        ];
        expand_owasp_pack("h", &mut policies, &mut transforms, &mut false, "proxy")
            .expect("expand")
            .expect("some");

        let types: Vec<&str> = transforms
            .iter()
            .map(|t| t.get("type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        let projection_idx = types
            .iter()
            .position(|&t| t == "json_projection")
            .expect("json_projection present");
        let envelope_idx = types
            .iter()
            .position(|&t| t == "json_envelope")
            .expect("json_envelope present");
        assert!(
            projection_idx < envelope_idx,
            "json_projection must run before json_envelope so it sees the real data, not the \
             envelope wrapper: {types:?}"
        );
    }

    #[test]
    fn api3_response_projection_appends_when_no_json_envelope_present() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api3"],
            "per_item": {
                "api3": {"response_exclude_fields": ["ssn"]},
            },
        }));
        let mut transforms = vec![serde_json::json!({"type": "html"})];
        expand_owasp_pack("h", &mut policies, &mut transforms, &mut false, "proxy")
            .expect("expand")
            .expect("some");
        let types: Vec<&str> = transforms
            .iter()
            .map(|t| t.get("type").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert_eq!(types, vec!["html", "json_projection"]);
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
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false, "proxy")
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
        let manifest = expand_owasp_pack(
            "h",
            &mut policies,
            &mut Vec::new(),
            &mut expose_openapi,
            "proxy",
        )
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
        let manifest = expand_owasp_pack(
            "h",
            &mut policies,
            &mut Vec::new(),
            &mut expose_openapi,
            "proxy",
        )
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

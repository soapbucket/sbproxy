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
//!     enable: all                # or: [api1, api4, api5, api8, api9]
//!     posture: report_only       # pack-wide default; a per_item entry
//!                                 # can override one item's posture
//!     per_item:
//!       api1:
//!         posture: enforce
//! ```
//!
//! Each of the ten OWASP API Security Top 10 (2023) items gets one row
//! in [`ITEM_TABLE`]. A row either synthesizes policy JSON (backing off
//! when the operator already authored a matching policy type) or, when
//! this pack version has no synthesis wired for the item yet, reports a
//! manifest-only outcome. The result is always visible: [`PackManifest`]
//! carries one [`PackManifestEntry`] per enabled item, so `enable: all`
//! never silently no-ops on an item the operator has no way to notice
//! is uncovered. `compiler::compile_origin` stores the manifest on
//! [`crate::snapshot::CompiledOrigin::owasp_pack_manifest`].
//!
//! Only `api1`'s row is populated in this version: a `object_authz`
//! entry with empty `object_rules` and `enumeration.enabled: true`,
//! which needs no operator-supplied ownership mapping to be safe to
//! synthesize. Every other row reports [`PackItemState::NotCovered`]
//! with a reason explaining what a later version of this pack adds.
//! `api1`'s `test_mode` field is `object_authz`'s own report-only
//! switch (mirrors the WAF `test_mode` switch, per its doc comment in
//! `sbproxy-modules::policy::object_authz`); this is the knob a
//! `posture: report_only` / `posture: enforce` setting threads into.
//! `security_headers` (the item this pack's design notes named as the
//! likely first safe-default row) has no such knob at the whole-policy
//! level: it always injects its configured headers unconditionally, so
//! there is nothing for a pack-level posture to thread into. `api1`'s
//! `object_authz` row was used instead so the posture-threading path is
//! exercised by a real knob rather than a no-op.
//!
//! `api1`'s manifest state is always [`PackItemState::NeedsOperatorInput`],
//! regardless of posture: `test_mode` still flips with `posture`, but
//! empty `object_rules` means no real ownership check is running
//! either way, only the enumeration fallback. The state names what is
//! missing (an operator-authored ownership mapping), not whether the
//! free fallback happens to be blocking or auditing.

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
    /// have synthesized something (`api1`'s enumeration-only
    /// `object_authz` fallback does), so `synthesized_types` can be
    /// non-empty here; the state names what is still missing, not
    /// whether anything at all is running.
    NeedsOperatorInput,
    /// This item is enabled but nothing was added to the compiled
    /// chain for it: either this pack version has no synthesis wired
    /// for it yet, or (per the design sketch) it has no gateway
    /// control today. The `reason` field says which.
    NotCovered,
}

/// One item's outcome inside a [`PackManifest`].
#[derive(Debug, Clone, Serialize)]
pub struct PackManifestEntry {
    /// Which OWASP API Security Top 10 item this entry describes.
    pub item: PackItem,
    /// The resolved outcome for this item.
    pub state: PackItemState,
    /// Human-readable explanation of `state`, safe to surface to an
    /// operator verbatim.
    pub reason: String,
    /// Config `type` strings the pack added to the origin's policy
    /// chain for this item. Empty for `OperatorAuthored` (the pack
    /// added nothing; the operator's own entry stands) and for
    /// `NotCovered`. Can be non-empty for `NeedsOperatorInput`: `api1`
    /// synthesizes an enumeration-only `object_authz` fallback while
    /// still reporting this state, because real coverage needs an
    /// operator-authored ownership mapping the fallback does not have.
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
}

/// Returns true when the JSON value's `type` field equals `wanted`.
///
/// A local copy of `compiler::config_type_is`: small enough that
/// sharing it across the module boundary is not worth the coupling.
fn config_type_is(value: &serde_json::Value, wanted: &str) -> bool {
    value.get("type").and_then(|v| v.as_str()) == Some(wanted)
}

/// A synthesized policy plus the manifest bookkeeping for one item.
struct ItemSynthesis {
    /// Policy JSON entries to append to the origin's `policies:` list.
    policies: Vec<serde_json::Value>,
    /// Config `type` strings of `policies`, for [`PackManifestEntry::synthesized_types`].
    synthesized_types: Vec<&'static str>,
    /// Resolved manifest state. Not necessarily a function of the
    /// posture passed in: `synth_object_authz` always returns
    /// `NeedsOperatorInput` regardless of posture, since posture only
    /// changes whether the fallback blocks or audits, not whether a
    /// real ownership mapping exists.
    state: PackItemState,
    /// Human-readable explanation for [`PackManifestEntry::reason`].
    reason: String,
}

/// One row of the per-item expansion table. `synth: None` means this
/// pack version has no synthesis wired for the item; `expand_owasp_pack`
/// reports [`PackItemState::NotCovered`] with `uncovered_reason`
/// instead.
struct ItemRow {
    /// The item this row describes.
    item: PackItem,
    /// Config `type` strings whose presence anywhere in the origin's
    /// (non-pack) policies makes the pack back off this item entirely.
    /// Empty when this row never backs off (nothing is ever
    /// synthesized for it).
    backoff_types: &'static [&'static str],
    /// Manifest reason used when a `backoff_types` entry is found.
    backoff_reason: &'static str,
    /// Synthesis function, when this row has one wired.
    synth: Option<fn(PackPosture) -> ItemSynthesis>,
    /// Manifest reason used when `synth` is `None`.
    uncovered_reason: &'static str,
}

/// Synthesizes `api1`/`api5`'s shared `object_authz` policy: empty
/// `object_rules` (no operator-supplied ownership mapping exists yet)
/// plus `enumeration.enabled: true`, which needs no mapping to detect
/// one principal touching an anomalous number of distinct object ids.
/// `posture` threads into `object_authz`'s own `test_mode` switch:
/// `report_only` sets `test_mode: true` (violations audited, request
/// passes); `enforce` sets `test_mode: false` (enumeration violations
/// blocked).
fn synth_object_authz(posture: PackPosture) -> ItemSynthesis {
    let test_mode = matches!(posture, PackPosture::ReportOnly);
    let policy = serde_json::json!({
        "type": "object_authz",
        "test_mode": test_mode,
        "enumeration": { "enabled": true },
    });
    let mode_note = if test_mode {
        "test_mode: true, so an enumeration hit is audited but the request passes"
    } else {
        "test_mode: false, so an enumeration hit is blocked"
    };
    // Ruling (plan ledger): the enumeration fallback ships active by
    // default regardless of posture, but the manifest state always
    // reads `needs_operator_input`, not `enforced`/`report_only`. The
    // state names what is missing (an ownership mapping), not whether
    // the free fallback happens to be blocking or auditing; claiming
    // `enforced` here would read as "BOLA is handled" when only the
    // anomaly-detection fallback is.
    ItemSynthesis {
        policies: vec![policy],
        synthesized_types: vec!["object_authz"],
        state: PackItemState::NeedsOperatorInput,
        reason: format!(
            "synthesized object_authz with empty object_rules and enumeration.enabled: true \
             ({mode_note}). This is enumeration-only coverage: real ownership verification \
             needs an operator-authored object_rules (or function_rules for BFLA) entry, which \
             this pack cannot infer."
        ),
    }
}

/// The per-item expansion table. One row per [`PackItem`], in
/// [`PackItem::ALL`] order. Only `api1`'s row synthesizes a policy in
/// this pack version; the rest report [`PackItemState::NotCovered`].
/// Tasks 2 and 3 fill in the remaining `synth` functions (and, for
/// `api4`/`api8`/`api9`, likely need this table's shape to grow: those
/// items synthesize more than one independently-backing-off policy
/// each, which a single `backoff_types`/`synth` pair per row does not
/// yet express).
const ITEM_TABLE: [ItemRow; 10] = [
    ItemRow {
        item: PackItem::Api1,
        backoff_types: &["object_authz", "bola"],
        backoff_reason: "origin already authors an object_authz/bola policy; the pack leaves it \
                          exactly as configured, including its own posture",
        synth: Some(synth_object_authz),
        uncovered_reason: "",
    },
    ItemRow {
        item: PackItem::Api2,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
        uncovered_reason: "no synthesis wired for this item; strong authentication is an \
                            operator choice of provider (jwt, oidc, api_key, bearer_token, \
                            etc.) the pack cannot make for you. Configure an authentication \
                            block directly.",
    },
    ItemRow {
        item: PackItem::Api3,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
        uncovered_reason: "no synthesis wired for this item; request-side coverage exists via \
                            openapi_validation or request_validator, but the pack cannot \
                            author a spec-shaped config for you, and there is no response-side \
                            (excessive data exposure) control at all today.",
    },
    ItemRow {
        item: PackItem::Api4,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
        uncovered_reason: "no synthesis wired for this item yet; a later version of this pack \
                            adds conservative defaults for request_limiting, rate_limiting, \
                            concurrent_limiting, and ddos_protection. Configure those policies \
                            directly until then.",
    },
    ItemRow {
        item: PackItem::Api5,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
        uncovered_reason: "no synthesis wired for this item yet; a later version of this pack \
                            shares api1's object_authz synthesis (function_rules for BFLA). \
                            Configure object_authz/bola directly until then.",
    },
    ItemRow {
        item: PackItem::Api6,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
        uncovered_reason: "no purpose-built control exists for sensitive-business-flow abuse; \
                            composing rate_limiting, concurrent_limiting, object_authz \
                            function_rules, and bot/web-bot-auth checks is the operator's job, \
                            since which flows are sensitive is inherently business-specific.",
    },
    ItemRow {
        item: PackItem::Api7,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
        uncovered_reason: "SSRF protection is not a policy the pack can toggle: the proxy's \
                            outbound dial path already refuses private/loopback/link-local \
                            upstream targets by default. Review \
                            proxy.extensions.upstream.allow_private_cidrs if it looks \
                            unusually broad.",
    },
    ItemRow {
        item: PackItem::Api8,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
        uncovered_reason: "no synthesis wired for this item yet; a later version of this pack \
                            adds security_headers, http_framing, and a test-mode waf default. \
                            Configure those policies directly until then.",
    },
    ItemRow {
        item: PackItem::Api9,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
        uncovered_reason: "no synthesis wired for this item yet; a later version of this pack \
                            turns on expose_openapi (a route-shape-disclosure tradeoff worth \
                            reviewing before enabling, not a free win).",
    },
    ItemRow {
        item: PackItem::Api10,
        backoff_types: &[],
        backoff_reason: "",
        synth: None,
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
/// concrete synthesized policies, appended to `policies` in place, and
/// removes the pseudo-policy entry itself so it never reaches
/// `sbproxy-modules::compile.rs`'s type-string match arms.
///
/// Returns `Ok(None)` when the origin has no `owasp_api_top10` entry.
/// Returns `Err` for: more than one `owasp_api_top10` entry on the
/// origin, an unknown item name in `enable` or `per_item`, a duplicate
/// item name within `enable`, a `per_item` override for an item not
/// named in `enable`, or a malformed `posture`/`enable` value.
///
/// `pub(crate)`: `compiler::compile_origin` is this crate's only
/// caller and its own public entry point (`compile_config`) already
/// covers the pack end to end, so this expansion step does not need
/// to be reachable outside `sbproxy-config` on its own.
pub(crate) fn expand_owasp_pack(
    hostname: &str,
    policies: &mut Vec<serde_json::Value>,
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
    }

    let mut entries = Vec::with_capacity(enabled_items.len());
    for item in PackItem::ALL {
        if !enabled_set.contains(&item) {
            continue;
        }
        let row = item_row(item).ok_or_else(|| {
            anyhow::anyhow!(
                "internal error: owasp_api_top10 has no ITEM_TABLE row for {item:?}; this is a \
                 bug in sbproxy-config, not a config error"
            )
        })?;
        let resolved_posture = per_item_posture.get(&item).copied().unwrap_or(pack_posture);

        let already_authored = !row.backoff_types.is_empty()
            && policies
                .iter()
                .any(|p| row.backoff_types.iter().any(|&t| config_type_is(p, t)));

        if already_authored {
            entries.push(PackManifestEntry {
                item,
                state: PackItemState::OperatorAuthored,
                reason: row.backoff_reason.to_string(),
                synthesized_types: Vec::new(),
            });
            continue;
        }

        match row.synth {
            Some(f) => {
                let synthesis = f(resolved_posture);
                policies.extend(synthesis.policies.iter().cloned());
                entries.push(PackManifestEntry {
                    item,
                    state: synthesis.state,
                    reason: synthesis.reason,
                    synthesized_types: synthesis.synthesized_types,
                });
            }
            None => {
                entries.push(PackManifestEntry {
                    item,
                    state: PackItemState::NotCovered,
                    reason: row.uncovered_reason.to_string(),
                    synthesized_types: Vec::new(),
                });
            }
        }
    }

    Ok(Some(PackManifest { entries }))
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
        let manifest = expand_owasp_pack("h", &mut policies).expect("expand");
        assert!(manifest.is_none());
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn unknown_item_name_in_enable_is_refused_with_accepted_list() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1", "api99"],
        }));
        let err = expand_owasp_pack("h", &mut policies)
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
        let err = expand_owasp_pack("h", &mut policies)
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
        let err = expand_owasp_pack("h", &mut policies)
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
        let err = expand_owasp_pack("h", &mut policies)
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
        let err = expand_owasp_pack("h", &mut policies)
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
        let err = expand_owasp_pack("h", &mut policies)
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
        expand_owasp_pack("h", &mut policies).expect("expand");
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
        let manifest = expand_owasp_pack("h", &mut policies)
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
        let manifest = expand_owasp_pack("h", &mut policies)
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
        let manifest = expand_owasp_pack("h", &mut policies)
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
        let manifest = expand_owasp_pack("h", &mut policies)
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
        let manifest = expand_owasp_pack("h", &mut policies)
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
        let manifest = expand_owasp_pack("h", &mut policies)
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
    fn items_with_no_synthesis_report_not_covered() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api2"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies)
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
}

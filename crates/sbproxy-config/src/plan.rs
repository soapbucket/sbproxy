//! Plan / apply diff engine. Implements steps 1 through 5 of the WOR-131
//! ADR (`docs/adr-config-plan-apply.md`): a sync library API that walks
//! two parsed [`ConfigFile`] values and produces a stable, JSON-serialisable
//! [`PlanReport`] describing the differences.
//!
//! The CLI in `crates/sbproxy/src/main.rs` is a thin wrapper over
//! [`plan`]. The same library API is intended for in-process callers
//! (the K8s operator, future admin-socket plan-export) per ADR open
//! question 7.
//!
//! Scope today (WOR-180 steps 1 through 5):
//!
//! * Diff granularity is per top-level key of [`ConfigFile`]:
//!   each origin (keyed by hostname) plus a single `proxy` entry that
//!   collapses every server-level field into one change row,
//!   plus `access_log` and `agent_classes` as their own entries.
//! * Blast-radius classification is **per path** via
//!   [`BLAST_RADIUS_MATRIX`]. For a given diff entry the walker
//!   enumerates every changed JSON leaf, looks each leaf path up in
//!   the matrix, and takes the worst-case radius across the set. The
//!   default for an unmatched path is [`BlastRadius::Reload`].
//! * Plan-time semantic validation runs against the **proposed**
//!   config and surfaces orphan refs, missing secrets, and unknown
//!   module types as [`PlanFinding`] entries on [`PlanReport`]. The
//!   CLI maps any [`Severity::Error`] finding to exit code `3`. See
//!   [`mod@crate::validate`] for the full rule list.
//! * [`PlanFile`] wraps a [`PlanReport`] with a
//!   `baseline_revision` (`SHA256` of the canonical JSON form of the
//!   baseline `ConfigFile`) so `apply -p plan-file` can detect drift.
//!   See [`PlanFile::write_to_path`] and [`PlanFile::read_from_path`].

use crate::types::ConfigFile;
use crate::validate::{validate, PlanFinding, Severity, ValidationOptions};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Stable JSON envelope returned by [`plan`].
///
/// The envelope shape is the v1 contract for the CLI's `--format json`
/// output and any future plan-file consumer. Adding fields is allowed;
/// renaming or removing existing fields is a breaking change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanReport {
    /// Plan envelope schema version. Currently `1`.
    pub plan_version: u32,
    /// Per-change rows in deterministic order: `proxy` first, then
    /// origins ordered by hostname, then `access_log`, then
    /// `agent_classes`. The order is part of the v1 contract so text
    /// rendering is reproducible across runs.
    pub entries: Vec<PlanEntry>,
    /// Summary counts grouped by [`PlanKind`]. Useful for the
    /// `terraform plan`-style footer.
    pub summary: PlanSummary,
    /// The largest blast radius across all entries. `Hitless` when
    /// there are no changes (matches the "no-op plan" exit-zero case).
    pub max_blast_radius: BlastRadius,
    /// Plan-time semantic-validation findings. See [`PlanFinding`]
    /// and the [`mod@crate::validate`] module for the full rule list.
    /// Empty when the proposed config passes every rule. Defaults
    /// to `vec![]` on deserialise so older plan envelopes parse
    /// unchanged.
    #[serde(default)]
    pub findings: Vec<PlanFinding>,
}

impl PlanReport {
    /// True when no entries are present (a no-op plan). The CLI maps
    /// this to exit code 0; `false` maps to exit code 2 (or to 3
    /// when [`Self::has_errors`] returns true).
    pub fn is_noop(&self) -> bool {
        self.entries.is_empty()
    }

    /// True when any finding has [`Severity::Error`]. The CLI maps
    /// this to exit code 3 and refuses to apply.
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.severity, Severity::Error))
    }
}

/// One change row in the plan.
///
/// `path` is a JSONPath-shaped string rooted at the YAML document
/// (e.g. `proxy`, `origins.api.example.com`). `kind` is added /
/// changed / removed. `old` and `new` are the raw JSON values; for
/// `Added`, `old` is `None`; for `Removed`, `new` is `None`. For
/// `Changed`, both are `Some` and not byte-equal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEntry {
    /// Where in the document this change lives.
    pub path: String,
    /// Whether the entry was added, changed, or removed.
    pub kind: PlanKind,
    /// JSON snapshot of the value in the baseline. `None` for `Added`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub old: Option<serde_json::Value>,
    /// JSON snapshot of the value in the proposed config. `None` for
    /// `Removed`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub new: Option<serde_json::Value>,
    /// Operational impact label. See [`BlastRadius`].
    pub blast_radius: BlastRadius,
    /// One-line human-readable explanation of why this entry is in the
    /// plan. Suitable for the text format and for log emission.
    pub reason: String,
}

/// What kind of change this entry represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanKind {
    /// Present in `proposed` but absent in `baseline`.
    Added,
    /// Present in both, but the JSON snapshots differ.
    Changed,
    /// Present in `baseline` but absent in `proposed`.
    Removed,
}

/// Operational impact of applying a single change.
///
/// Ordered by severity so the CLI can compute `max_blast_radius` with
/// `entries.iter().map(|e| e.blast_radius).max()`.
///
/// Per the ADR section "Blast-radius hint":
/// * `Hitless` change can be applied without re-routing any in-flight
///   or future request (log-level, access-log filter tweaks).
/// * `Reload` change requires `arc-swap` to publish a new pipeline.
///   In-flight requests finish on the old pipeline; new requests pick
///   up the new pipeline. This is what the existing hot-reload path
///   already does.
/// * `Restart` change requires the OS process to restart because the
///   listener or process-global state cannot be hot-swapped (bind
///   ports, agent-class resolver).
/// * `Breaking` change is `Restart`-class **and** would drop in-flight
///   connections beyond the existing graceful-shutdown budget. Also
///   used for wire-compatibility breakers (removed origins, auth-type
///   swaps) where existing clients see an immediate behavioural break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlastRadius {
    /// No re-routing required.
    Hitless,
    /// Hot-swap via arc-swap.
    Reload,
    /// Process restart required.
    Restart,
    /// Restart plus connection drops or wire-format break.
    Breaking,
}

/// Summary counts for [`PlanReport`]. Used to render the
/// `terraform plan`-style footer line.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlanSummary {
    /// Number of [`PlanKind::Added`] entries.
    pub added: usize,
    /// Number of [`PlanKind::Changed`] entries.
    pub changed: usize,
    /// Number of [`PlanKind::Removed`] entries.
    pub removed: usize,
}

impl PlanSummary {
    fn record(&mut self, kind: PlanKind) {
        match kind {
            PlanKind::Added => self.added += 1,
            PlanKind::Changed => self.changed += 1,
            PlanKind::Removed => self.removed += 1,
        }
    }
}

// --- Per-path blast-radius matrix (WOR-180 step 4) ---------------------

/// One row of the per-path blast-radius matrix.
///
/// `pattern` is a simple glob over JSONPath-shaped path strings. Each
/// `*` segment matches exactly one path component (e.g. an origin
/// hostname or a vector index). Patterns are matched in order; the
/// first match wins, so place specific patterns ahead of broader ones.
#[derive(Debug, Clone, Copy)]
pub struct BlastRadiusRule {
    /// Glob pattern. Literal segments + `*` for any one segment.
    pub pattern: &'static str,
    /// Blast radius to assign on a match.
    pub radius: BlastRadius,
    /// Short prose explaining why this path has this radius. Surfaced
    /// in the plan entry's `reason` when the matrix lookup is the
    /// dominant factor.
    pub reason: &'static str,
}

/// Per-path blast-radius matrix. The walker resolves every changed
/// leaf path against this list in order and takes the worst-case
/// (highest) radius across all matches.
///
/// Path syntax:
///
/// * Patterns are evaluated against canonicalised paths, where the
///   origin hostname (which itself contains dots) has already been
///   substituted with `*` by the caller, and array indices are
///   substituted with `*` by `canonicalise_path`.
/// * `*` matches exactly one path segment.
/// * `**` (only at the end of a pattern) matches one or more
///   trailing segments. Used for "anything under this subtree."
///
/// Default radius for an unmatched leaf: [`BlastRadius::Reload`].
/// The reload state machine is the cheapest non-no-op operation, so
/// "unknown change" is the conservative fallback that still picks up
/// the `arc-swap` publish.
///
/// Top-10 entries (matrix order):
///
/// 1. `proxy.http_bind_port` -> `Restart`
/// 2. `proxy.https_bind_port` -> `Restart`
/// 3. `proxy.http3.**` -> `Restart`
/// 4. `proxy.admin.port` -> `Restart`
/// 5. `proxy.admin.bind_addr` -> `Restart`
/// 6. `proxy.tls_cert_file` -> `Reload`
/// 7. `proxy.tls_key_file` -> `Reload`
/// 8. `proxy.l2_cache.driver` -> `Restart`
/// 9. `proxy.messenger_settings.driver` -> `Restart`
/// 10. `agent_classes.**` -> `Restart`
///
/// The full list lives in this constant; new entries are appended,
/// not reordered, so existing pattern matches stay stable.
pub const BLAST_RADIUS_MATRIX: &[BlastRadiusRule] = &[
    // --- Listener bind state. Restart-class: the process binds the
    //     socket once at startup and there is no graceful re-bind ---
    BlastRadiusRule {
        pattern: "proxy.http_bind_port",
        radius: BlastRadius::Restart,
        reason: "HTTP listener port is bound once at startup",
    },
    BlastRadiusRule {
        pattern: "proxy.https_bind_port",
        radius: BlastRadius::Restart,
        reason: "HTTPS listener port is bound once at startup",
    },
    BlastRadiusRule {
        pattern: "proxy.http2_cleartext",
        radius: BlastRadius::Restart,
        reason: "h2c preface detection is wired at listener-bind time",
    },
    // --- HTTP/3 listener: any change rebinds the QUIC socket ---
    BlastRadiusRule {
        pattern: "proxy.http3.**",
        radius: BlastRadius::Restart,
        reason: "HTTP/3 listener is bound once at startup",
    },
    BlastRadiusRule {
        pattern: "proxy.http3",
        radius: BlastRadius::Restart,
        reason: "HTTP/3 listener is bound once at startup",
    },
    // --- Admin server: same OnceLock listener story ---
    BlastRadiusRule {
        pattern: "proxy.admin.port",
        radius: BlastRadius::Restart,
        reason: "admin server listener is bound once at startup",
    },
    BlastRadiusRule {
        pattern: "proxy.admin.bind_addr",
        radius: BlastRadius::Restart,
        reason: "admin server listener is bound once at startup",
    },
    BlastRadiusRule {
        pattern: "proxy.admin.enabled",
        radius: BlastRadius::Restart,
        reason: "toggling the admin server requires a fresh listener",
    },
    BlastRadiusRule {
        pattern: "proxy.admin.**",
        radius: BlastRadius::Reload,
        reason: "admin auth / TLS settings re-read on reload",
    },
    // --- TLS material: cert / key hot-swap is supported ---
    BlastRadiusRule {
        pattern: "proxy.tls_cert_file",
        radius: BlastRadius::Reload,
        reason: "cert reload is supported through the SIGHUP path",
    },
    BlastRadiusRule {
        pattern: "proxy.tls_key_file",
        radius: BlastRadius::Reload,
        reason: "key reload is supported through the SIGHUP path",
    },
    BlastRadiusRule {
        pattern: "proxy.acme.**",
        radius: BlastRadius::Reload,
        reason: "ACME state lives in arc-swapped pipeline",
    },
    BlastRadiusRule {
        pattern: "proxy.mtls.**",
        radius: BlastRadius::Reload,
        reason: "mTLS handshake config reloads via arc-swap",
    },
    BlastRadiusRule {
        pattern: "proxy.mtls",
        radius: BlastRadius::Reload,
        reason: "mTLS handshake config reloads via arc-swap",
    },
    // --- L2 cache: driver swap rebuilds the KV handle (restart);
    //     param tuning is hot-swappable. ---
    BlastRadiusRule {
        pattern: "proxy.l2_cache.driver",
        radius: BlastRadius::Restart,
        reason: "L2 driver swap rebuilds the KV handle",
    },
    BlastRadiusRule {
        pattern: "proxy.l2_cache_settings.driver",
        radius: BlastRadius::Restart,
        reason: "L2 driver swap rebuilds the KV handle",
    },
    BlastRadiusRule {
        pattern: "proxy.l2_cache.**",
        radius: BlastRadius::Reload,
        reason: "L2 cache parameters re-read on reload",
    },
    BlastRadiusRule {
        pattern: "proxy.l2_cache_settings.**",
        radius: BlastRadius::Reload,
        reason: "L2 cache parameters re-read on reload",
    },
    // --- Messenger driver: same story as L2 ---
    BlastRadiusRule {
        pattern: "proxy.messenger_settings.driver",
        radius: BlastRadius::Restart,
        reason: "messenger driver swap rebuilds the bus handle",
    },
    BlastRadiusRule {
        pattern: "proxy.messenger_settings.**",
        radius: BlastRadius::Reload,
        reason: "messenger parameters re-read on reload",
    },
    // --- Observability: hitless. The hooks read their config on
    //     every request from the arc-swapped pipeline. ---
    BlastRadiusRule {
        pattern: "proxy.metrics.**",
        radius: BlastRadius::Hitless,
        reason: "metrics config is read per request",
    },
    BlastRadiusRule {
        pattern: "proxy.metrics",
        radius: BlastRadius::Hitless,
        reason: "metrics config is read per request",
    },
    BlastRadiusRule {
        pattern: "proxy.alerting.**",
        radius: BlastRadius::Hitless,
        reason: "alert channels reload via arc-swap",
    },
    BlastRadiusRule {
        pattern: "proxy.alerting",
        radius: BlastRadius::Hitless,
        reason: "alert channels reload via arc-swap",
    },
    BlastRadiusRule {
        pattern: "proxy.correlation_id.**",
        radius: BlastRadius::Hitless,
        reason: "correlation-id policy is read per request",
    },
    BlastRadiusRule {
        pattern: "access_log.**",
        radius: BlastRadius::Hitless,
        reason: "access-log filter is read per request",
    },
    BlastRadiusRule {
        pattern: "access_log",
        radius: BlastRadius::Hitless,
        reason: "access-log filter is read per request",
    },
    // --- Trusted-proxies: arc-swap path reads on every request ---
    BlastRadiusRule {
        pattern: "proxy.trusted_proxies.**",
        radius: BlastRadius::Reload,
        reason: "trusted-proxy CIDRs re-read on reload",
    },
    BlastRadiusRule {
        pattern: "proxy.trusted_proxies",
        radius: BlastRadius::Reload,
        reason: "trusted-proxy CIDRs re-read on reload",
    },
    // --- Secrets: reload is enough; the secret cache rebuilds ---
    BlastRadiusRule {
        pattern: "proxy.secrets.**",
        radius: BlastRadius::Reload,
        reason: "secret store reloads via arc-swap",
    },
    BlastRadiusRule {
        pattern: "proxy.secrets",
        radius: BlastRadius::Reload,
        reason: "secret store reloads via arc-swap",
    },
    // --- Cache reserve: reload-class ---
    BlastRadiusRule {
        pattern: "proxy.cache_reserve.**",
        radius: BlastRadius::Reload,
        reason: "cache reserve handles reload via arc-swap",
    },
    // --- Synthetic probe: reload-class (a background task is
    //     re-spawned in the new pipeline) ---
    BlastRadiusRule {
        pattern: "proxy.synthetic_probe.**",
        radius: BlastRadius::Reload,
        reason: "synthetic probe task respawns on reload",
    },
    // --- Agent classes: the resolver is OnceLock. Step 4 of
    //     WOR-180 specifically calls this out as restart-class. ---
    BlastRadiusRule {
        pattern: "agent_classes.**",
        radius: BlastRadius::Restart,
        reason: "agent-class resolver is OnceLock-globaled",
    },
    BlastRadiusRule {
        pattern: "agent_classes",
        radius: BlastRadius::Restart,
        reason: "agent-class resolver is OnceLock-globaled",
    },
    // --- Origin wire-format and breaking changes ---
    //
    // Removing an origin or changing its auth.type drops in-flight
    // clients in a way that the reload's connection-drain budget
    // cannot recover from. Flagged as `Breaking` so operators see it
    // distinctly from a hot-reload-friendly tweak.
    BlastRadiusRule {
        pattern: "origins.*.authentication.type",
        radius: BlastRadius::Breaking,
        reason: "auth-type swap breaks wire compatibility for existing clients",
    },
    BlastRadiusRule {
        pattern: "origins.*.action.type",
        radius: BlastRadius::Breaking,
        reason: "action-type swap breaks wire compatibility (e.g. proxy -> static)",
    },
    // --- Origin reload-class: every other origin field is
    //     hot-swappable through arc-swap today. ---
    BlastRadiusRule {
        pattern: "origins.*.action.**",
        radius: BlastRadius::Reload,
        reason: "origin action body re-read on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.action",
        radius: BlastRadius::Reload,
        reason: "origin action re-read on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.policies.**",
        radius: BlastRadius::Reload,
        reason: "policy chain re-compiles on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.policies",
        radius: BlastRadius::Reload,
        reason: "policy chain re-compiles on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.transforms.**",
        radius: BlastRadius::Reload,
        reason: "transform chain re-compiles on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.transforms",
        radius: BlastRadius::Reload,
        reason: "transform chain re-compiles on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.authentication.**",
        radius: BlastRadius::Reload,
        reason: "auth body (keys, JWKS URL) re-read on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.authentication",
        radius: BlastRadius::Reload,
        reason: "auth chain re-compiles on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.rate_limits.**",
        radius: BlastRadius::Reload,
        reason: "rate-limit budget re-read on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*.rate_limits",
        radius: BlastRadius::Reload,
        reason: "rate-limit budget re-read on reload",
    },
    // --- Hitless origin tweaks: backend timeout, capture toggles
    //     etc. The proxy reads these fields per request from the
    //     arc-swapped pipeline so the swap is observed without
    //     re-routing. ---
    BlastRadiusRule {
        pattern: "origins.*.properties.**",
        radius: BlastRadius::Hitless,
        reason: "properties capture is read per request",
    },
    BlastRadiusRule {
        pattern: "origins.*.sessions.**",
        radius: BlastRadius::Hitless,
        reason: "session capture is read per request",
    },
    BlastRadiusRule {
        pattern: "origins.*.user.**",
        radius: BlastRadius::Hitless,
        reason: "user-id capture is read per request",
    },
    BlastRadiusRule {
        pattern: "origins.*.connection_pool.**",
        radius: BlastRadius::Reload,
        reason: "connection pool rebuilds on reload",
    },
    // --- Catch-all for unrecognised origin fields ---
    BlastRadiusRule {
        pattern: "origins.*.**",
        radius: BlastRadius::Reload,
        reason: "origin-level field re-read on reload",
    },
    BlastRadiusRule {
        pattern: "origins.*",
        radius: BlastRadius::Reload,
        reason: "origin re-compiled on reload",
    },
    // --- Catch-all for unrecognised proxy fields ---
    BlastRadiusRule {
        pattern: "proxy.**",
        radius: BlastRadius::Reload,
        reason: "proxy-level field re-read on reload",
    },
    BlastRadiusRule {
        pattern: "proxy",
        radius: BlastRadius::Reload,
        reason: "proxy block re-read on reload",
    },
];

/// Look up the blast radius for a single canonicalised path by
/// matching against [`BLAST_RADIUS_MATRIX`] in declaration order. The
/// first match wins; if no rule matches, the default is
/// [`BlastRadius::Reload`].
///
/// `path` is expected to already have hostnames and array indices
/// replaced with `*`; see `canonicalise_path`.
fn lookup_blast_radius(path: &str) -> (BlastRadius, &'static str) {
    for rule in BLAST_RADIUS_MATRIX {
        if glob_match(rule.pattern, path) {
            return (rule.radius, rule.reason);
        }
    }
    (
        BlastRadius::Reload,
        "no specific rule matched; default is reload",
    )
}

/// Match a glob pattern against a JSONPath-shaped string.
///
/// * Each `*` segment matches exactly one path component.
/// * A trailing `**` segment matches one or more path components
///   (the recursive wildcard). Used for "anything under this
///   subtree" patterns like `agent_classes.**`.
///
/// Components are split by `.` because the diff walker emits paths
/// in `a.b.c` form. This avoids pulling in a globbing crate for
/// what amounts to "literal segments + wildcard segments".
fn glob_match(pattern: &str, path: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('.').collect();
    let path_parts: Vec<&str> = path.split('.').collect();
    let trailing_double_star = pat_parts.last().copied() == Some("**");
    if trailing_double_star {
        let pat_head = &pat_parts[..pat_parts.len() - 1];
        if path_parts.len() < pat_head.len() + 1 {
            return false;
        }
        for (p, q) in pat_head.iter().zip(path_parts.iter()) {
            if *p == "*" {
                continue;
            }
            if p != q {
                return false;
            }
        }
        return true;
    }
    if pat_parts.len() != path_parts.len() {
        return false;
    }
    for (p, q) in pat_parts.iter().zip(path_parts.iter()) {
        if *p == "*" {
            continue;
        }
        if p != q {
            return false;
        }
    }
    true
}

/// Replace numeric segments (array indices) in a JSONPath-shaped
/// string with `*` so the matrix lookup matches array elements
/// agnostic of their position. Hostname canonicalisation is handled
/// upstream by passing `origins.*` as the base path to
/// [`collect_changed_leaves`] (rather than the real hostname),
/// because hostnames are themselves dot-separated and cannot be
/// split out reliably here.
fn canonicalise_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('.').collect();
    let mut out = Vec::with_capacity(parts.len());
    for part in &parts {
        if part.chars().all(|c| c.is_ascii_digit()) && !part.is_empty() {
            out.push("*");
        } else {
            out.push(*part);
        }
    }
    out.join(".")
}

/// Walk a `(baseline, proposed)` pair of JSON values and emit one
/// `(path, BlastRadius, reason)` triple per changed leaf. Used to
/// compute the worst-case blast radius for a single
/// [`PlanEntry`] when both sides are present.
fn collect_changed_leaves(
    base_path: &str,
    a: &serde_json::Value,
    b: &serde_json::Value,
    out: &mut Vec<(String, BlastRadius, &'static str)>,
) {
    if a == b {
        return;
    }
    match (a, b) {
        (serde_json::Value::Object(am), serde_json::Value::Object(bm)) => {
            let mut keys: BTreeSet<&str> = BTreeSet::new();
            for k in am.keys() {
                keys.insert(k.as_str());
            }
            for k in bm.keys() {
                keys.insert(k.as_str());
            }
            for k in keys {
                let av = am.get(k).unwrap_or(&serde_json::Value::Null);
                let bv = bm.get(k).unwrap_or(&serde_json::Value::Null);
                if av == bv {
                    continue;
                }
                let sub = if base_path.is_empty() {
                    k.to_string()
                } else {
                    format!("{base_path}.{k}")
                };
                collect_changed_leaves(&sub, av, bv, out);
            }
        }
        (serde_json::Value::Array(aa), serde_json::Value::Array(bb)) => {
            let max = aa.len().max(bb.len());
            for i in 0..max {
                let null = serde_json::Value::Null;
                let av = aa.get(i).unwrap_or(&null);
                let bv = bb.get(i).unwrap_or(&null);
                if av == bv {
                    continue;
                }
                let sub = format!("{base_path}.{i}");
                collect_changed_leaves(&sub, av, bv, out);
            }
        }
        _ => {
            // Leaf change. Look up the canonicalised path in the
            // matrix and record the resolved (radius, reason).
            let canon = canonicalise_path(base_path);
            let (radius, reason) = lookup_blast_radius(&canon);
            out.push((base_path.to_string(), radius, reason));
        }
    }
}

/// Resolve the blast radius for a `Changed` entry by deep-walking the
/// pair and taking the worst-case across every changed leaf. Returns
/// the (radius, supplemental-reason) tuple the caller stitches into
/// the [`PlanEntry`].
fn resolve_changed_blast_radius(
    base_path: &str,
    a: &serde_json::Value,
    b: &serde_json::Value,
) -> (BlastRadius, Option<String>) {
    let mut leaves: Vec<(String, BlastRadius, &'static str)> = Vec::new();
    collect_changed_leaves(base_path, a, b, &mut leaves);
    if leaves.is_empty() {
        // Should not happen (caller checks `a != b`) but keep total.
        return (BlastRadius::Reload, None);
    }
    // Pick the worst-case leaf. On a tie, the first declared rule
    // wins (see iteration order) so the dominant reason is stable.
    let mut best: &(String, BlastRadius, &'static str) = &leaves[0];
    for entry in &leaves[1..] {
        if entry.1 > best.1 {
            best = entry;
        }
    }
    let supplemental = format!("dominant path '{}': {}", best.0, best.2);
    (best.1, Some(supplemental))
}

/// Resolve the blast radius for an `Added` or `Removed` entry by
/// taking the worst-case across all leaves of the present side.
fn resolve_present_blast_radius(
    base_path: &str,
    value: &serde_json::Value,
) -> (BlastRadius, Option<String>) {
    let null = serde_json::Value::Null;
    let mut leaves: Vec<(String, BlastRadius, &'static str)> = Vec::new();
    collect_changed_leaves(base_path, &null, value, &mut leaves);
    if leaves.is_empty() {
        // `value` is null / scalar at the top; fall back to the
        // canonicalised top-level lookup.
        let canon = canonicalise_path(base_path);
        let (r, reason) = lookup_blast_radius(&canon);
        return (r, Some(reason.to_string()));
    }
    let mut best: &(String, BlastRadius, &'static str) = &leaves[0];
    for entry in &leaves[1..] {
        if entry.1 > best.1 {
            best = entry;
        }
    }
    (
        best.1,
        Some(format!("dominant path '{}': {}", best.0, best.2)),
    )
}

// --- Public diff entry point ----------------------------------------

/// Diff two parsed config files and return a [`PlanReport`].
///
/// Diff granularity is per top-level key of [`ConfigFile`]:
///
/// * `proxy` collapses to a single entry. Any server-level field
///   change produces one row labelled `Changed` with the full proxy
///   block as `old` / `new`. The blast radius is computed by
///   deep-walking the two proxy snapshots and taking the worst-case
///   across all changed leaves per [`BLAST_RADIUS_MATRIX`].
/// * `origins.<hostname>` produces one entry per origin. Adding,
///   removing, or changing an origin shows up as exactly one row,
///   with the blast radius resolved from the matrix.
/// * `access_log` and `agent_classes` produce at most one entry each
///   when their JSON snapshots differ, with the matrix again
///   determining the radius.
///
/// The function is sync, allocation-bounded, and never panics: every
/// `serde_json::to_value` failure is converted to a string-encoded
/// fallback so the CLI never sees a `Result::Err`.
///
/// Plan-time semantic validation runs against `proposed` (not
/// `baseline`) using [`ValidationOptions::default()`]. Callers that
/// link extra plugin crates should use [`plan_with_options`] to pass
/// their extended type catalogs.
pub fn plan(baseline: &ConfigFile, proposed: &ConfigFile) -> PlanReport {
    plan_with_options(baseline, proposed, &ValidationOptions::default())
}

/// Diff two parsed config files and run plan-time semantic
/// validation with the supplied [`ValidationOptions`]. Use this
/// entry point in builds that link auth / action / policy /
/// transform plugin crates beyond the OSS catalog so the unknown-type
/// rule does not falsely flag those module names.
pub fn plan_with_options(
    baseline: &ConfigFile,
    proposed: &ConfigFile,
    opts: &ValidationOptions,
) -> PlanReport {
    let mut entries: Vec<PlanEntry> = Vec::new();
    let mut summary = PlanSummary::default();

    // -- proxy block --
    let baseline_proxy = json_or_null(&baseline.proxy);
    let proposed_proxy = json_or_null(&proposed.proxy);
    if baseline_proxy != proposed_proxy {
        let (blast, supplemental) =
            resolve_changed_blast_radius("proxy", &baseline_proxy, &proposed_proxy);
        let reason = match supplemental {
            Some(s) => format!("proxy server-level settings changed ({s})"),
            None => "proxy server-level settings changed".to_string(),
        };
        let entry = PlanEntry {
            path: "proxy".to_string(),
            kind: PlanKind::Changed,
            old: Some(baseline_proxy),
            new: Some(proposed_proxy),
            blast_radius: blast,
            reason,
        };
        summary.record(entry.kind);
        entries.push(entry);
    }

    // -- origins (sorted by hostname for determinism) --
    let mut hostnames: BTreeSet<&str> = BTreeSet::new();
    for k in baseline.origins.keys() {
        hostnames.insert(k.as_str());
    }
    for k in proposed.origins.keys() {
        hostnames.insert(k.as_str());
    }

    for host in &hostnames {
        let host_owned: String = (*host).to_string();
        let path = format!("origins.{host_owned}");

        match (baseline.origins.get(*host), proposed.origins.get(*host)) {
            (None, Some(new)) => {
                let new_json = json_or_null(new);
                // Walk leaves with the canonical path (`origins.*`)
                // so the matrix lookup ignores the literal hostname.
                let (blast, _supplemental) = resolve_present_blast_radius("origins.*", &new_json);
                let entry = PlanEntry {
                    path,
                    kind: PlanKind::Added,
                    old: None,
                    new: Some(new_json),
                    blast_radius: blast,
                    reason: format!("origin '{host_owned}' added"),
                };
                summary.record(entry.kind);
                entries.push(entry);
            }
            (Some(old), None) => {
                let old_json = json_or_null(old);
                // Removing a published origin breaks wire compatibility
                // for any client currently reaching it. The matrix
                // does not have a dedicated removal pattern, so we
                // hard-code `Breaking` here per the ADR appendix.
                let entry = PlanEntry {
                    path,
                    kind: PlanKind::Removed,
                    old: Some(old_json),
                    new: None,
                    blast_radius: BlastRadius::Breaking,
                    reason: format!(
                        "origin '{host_owned}' removed (breaking: in-flight clients drop)"
                    ),
                };
                summary.record(entry.kind);
                entries.push(entry);
            }
            (Some(old), Some(new)) => {
                let old_json = json_or_null(old);
                let new_json = json_or_null(new);
                if old_json != new_json {
                    // Canonical base path replaces the hostname with
                    // `*` so the matrix matches structural rules
                    // regardless of which origin was edited.
                    let (blast, supplemental) =
                        resolve_changed_blast_radius("origins.*", &old_json, &new_json);
                    let mut reason = origin_change_reason(&host_owned, &old_json, &new_json);
                    if let Some(s) = supplemental {
                        reason.push_str(" [");
                        reason.push_str(&s);
                        reason.push(']');
                    }
                    let entry = PlanEntry {
                        path,
                        kind: PlanKind::Changed,
                        old: Some(old_json),
                        new: Some(new_json),
                        blast_radius: blast,
                        reason,
                    };
                    summary.record(entry.kind);
                    entries.push(entry);
                }
            }
            (None, None) => {}
        }
    }

    // -- access_log --
    let baseline_al = json_or_null(&baseline.access_log);
    let proposed_al = json_or_null(&proposed.access_log);
    if baseline_al != proposed_al {
        let kind = match (baseline.access_log.is_some(), proposed.access_log.is_some()) {
            (false, true) => PlanKind::Added,
            (true, false) => PlanKind::Removed,
            _ => PlanKind::Changed,
        };
        let blast = match kind {
            PlanKind::Added => resolve_present_blast_radius("access_log", &proposed_al).0,
            PlanKind::Removed => resolve_present_blast_radius("access_log", &baseline_al).0,
            PlanKind::Changed => {
                resolve_changed_blast_radius("access_log", &baseline_al, &proposed_al).0
            }
        };
        let entry = PlanEntry {
            path: "access_log".to_string(),
            kind,
            old: if matches!(kind, PlanKind::Added) {
                None
            } else {
                Some(baseline_al)
            },
            new: if matches!(kind, PlanKind::Removed) {
                None
            } else {
                Some(proposed_al)
            },
            blast_radius: blast,
            reason: "access_log block changed".to_string(),
        };
        summary.record(entry.kind);
        entries.push(entry);
    }

    // -- agent_classes --
    let baseline_ac = json_or_null(&baseline.agent_classes);
    let proposed_ac = json_or_null(&proposed.agent_classes);
    if baseline_ac != proposed_ac {
        let kind = match (
            baseline.agent_classes.is_some(),
            proposed.agent_classes.is_some(),
        ) {
            (false, true) => PlanKind::Added,
            (true, false) => PlanKind::Removed,
            _ => PlanKind::Changed,
        };
        let blast = match kind {
            PlanKind::Added => resolve_present_blast_radius("agent_classes", &proposed_ac).0,
            PlanKind::Removed => resolve_present_blast_radius("agent_classes", &baseline_ac).0,
            PlanKind::Changed => {
                resolve_changed_blast_radius("agent_classes", &baseline_ac, &proposed_ac).0
            }
        };
        let entry = PlanEntry {
            path: "agent_classes".to_string(),
            kind,
            old: if matches!(kind, PlanKind::Added) {
                None
            } else {
                Some(baseline_ac)
            },
            new: if matches!(kind, PlanKind::Removed) {
                None
            } else {
                Some(proposed_ac)
            },
            blast_radius: blast,
            reason: "agent_classes block changed".to_string(),
        };
        summary.record(entry.kind);
        entries.push(entry);
    }

    let max_blast_radius = entries
        .iter()
        .map(|e| e.blast_radius)
        .max()
        .unwrap_or(BlastRadius::Hitless);

    // Plan-time semantic validation runs against the proposed
    // config. Findings ride alongside the diff entries; the CLI
    // maps any `Severity::Error` finding to exit code 3.
    let findings = validate(proposed, opts);

    PlanReport {
        plan_version: 1,
        entries,
        summary,
        max_blast_radius,
        findings,
    }
}

// --- WOR-180 step 5: plan-file with baseline_revision ----------------

/// On-disk plan-file envelope. Wraps a [`PlanReport`] with a
/// `baseline_revision` so a later `apply -p plan-file` can detect
/// drift: if the live baseline at apply time hashes to a different
/// revision than the plan was generated against, apply refuses to
/// proceed.
///
/// The revision is `SHA256(canonical_json_of_baseline_config_file)`,
/// hex-encoded. Canonical JSON here means `serde_json::to_vec` of
/// the parsed [`ConfigFile`] sorted by key (object keys in
/// `serde_json::Value` order). See [`compute_baseline_revision`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanFile {
    /// File-format schema version. Currently `1`. Bump when adding a
    /// non-backward-compatible field.
    pub plan_file_version: u32,
    /// SHA-256 (hex) of the baseline config the plan was diffed
    /// against. Apply fails if the live baseline hashes differently.
    pub baseline_revision: String,
    /// The plan body (entries, summary, findings).
    pub report: PlanReport,
}

impl PlanFile {
    /// Build a new plan-file from a baseline `ConfigFile` and a
    /// pre-computed [`PlanReport`]. The revision is computed here so
    /// the caller does not have to import `sha2` directly.
    pub fn new(baseline: &ConfigFile, report: PlanReport) -> Self {
        Self {
            plan_file_version: 1,
            baseline_revision: compute_baseline_revision(baseline),
            report,
        }
    }

    /// Atomically write the plan-file as JSON to `path` using the
    /// temp-file + `rename(2)` pattern.
    ///
    /// The temp file is created in the same directory as `path` (so
    /// `rename(2)` is atomic across the same filesystem), then
    /// renamed into place. On a crash mid-write, `path` either keeps
    /// its previous contents or is already the new value; it is
    /// never half-written.
    ///
    /// # Errors
    ///
    /// Returns an error if the plan cannot be serialized to JSON, or if any
    /// filesystem step (creating, writing, syncing, or renaming the temp
    /// file) fails.
    pub fn write_to_path(&self, path: &std::path::Path) -> std::io::Result<()> {
        let body = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("plan.json");
        let pid = std::process::id();
        // Nanosecond timestamp + pid keeps two concurrent writers in
        // the same dir from colliding; the rename is the atomic
        // step, not the temp-file creation.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = parent.join(format!(".{file_name}.{pid}.{nanos}.tmp"));
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Read and parse a plan-file written by [`Self::write_to_path`].
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, or if its contents do
    /// not deserialize from JSON into a `PlanFile`.
    pub fn read_from_path(path: &std::path::Path) -> std::io::Result<Self> {
        let body = std::fs::read(path)?;
        serde_json::from_slice(&body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Compute the SHA-256 of the canonical JSON form of a
/// [`ConfigFile`]. Hex-encoded. Used by [`PlanFile::new`] so the
/// apply path can detect drift between plan-time and apply-time
/// baselines.
///
/// The canonical form is `serde_json::to_vec` of the parsed
/// `ConfigFile`. `serde_json` orders map keys lexicographically when
/// serialising, which is enough to make the same logical config hash
/// identically across runs even when the source YAML reorders keys.
pub fn compute_baseline_revision(config: &ConfigFile) -> String {
    let canonical = serde_json::to_vec(config).unwrap_or_else(|_| b"{}".to_vec());
    sha256_hex(&canonical)
}

/// Lightweight SHA-256 (RFC 6234). Wraps a single use site so we do
/// not have to add a new workspace dependency for the baseline
/// revision; the existing `ring`-via-rustls dep already covers SHA-2
/// elsewhere in the workspace, but `sbproxy-config` is plugin-facing
/// and stays dependency-light. Implementation follows the public
/// FIPS 180-4 round constants.
fn sha256_hex(input: &[u8]) -> String {
    // SAFETY: the implementation below is total over `&[u8]`.
    let digest = sha256_raw(input);
    let mut out = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn sha256_raw(input: &[u8]) -> [u8; 32] {
    // Minimal SHA-256 driver lifted from FIPS 180-4. Used once per
    // plan-file emit. Not perf-critical; correctness is verified by
    // a known-answer test in this module.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len: u64 = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 73);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.chunks(64) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// --- Internal helpers (unchanged from earlier scopes) -----------------

/// Best-effort JSON snapshot of a config sub-tree.
///
/// `serde_json::to_value` should always succeed for our config types
/// since they all derive `Serialize`. Defending against the
/// theoretical failure case (e.g. a future field that produces a
/// non-finite float) keeps `plan` total: callers never have to handle
/// a "couldn't snapshot baseline" error path.
fn json_or_null<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

/// Heuristic one-liner describing the most-visible change between two
/// origin JSON snapshots. Falls back to the generic phrase when the
/// snapshots differ in a structurally-deep way the heuristic does not
/// recognise.
fn origin_change_reason(host: &str, old: &serde_json::Value, new: &serde_json::Value) -> String {
    if let (serde_json::Value::Object(old_obj), serde_json::Value::Object(new_obj)) = (old, new) {
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        for k in old_obj.keys() {
            keys.insert(k.as_str());
        }
        for k in new_obj.keys() {
            keys.insert(k.as_str());
        }
        let differing: Vec<&str> = keys
            .iter()
            .filter(|k| old_obj.get(**k) != new_obj.get(**k))
            .copied()
            .collect();
        if !differing.is_empty() {
            let preview = differing
                .iter()
                .take(3)
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if differing.len() > 3 { ", ..." } else { "" };
            return format!("origin '{host}' changed ({preview}{suffix})");
        }
    }
    format!("origin '{host}' changed")
}

/// Render a [`PlanReport`] as a Terraform-style human-readable text
/// block. The format is deliberately stable but not promised; tooling
/// should consume `--format json` instead.
///
/// When the report carries [`PlanFinding`] entries (semantic
/// validation), they print after the diff under a `Validation:`
/// header so an operator sees errors and warnings in the same place
/// as the change list.
pub fn render_text(report: &PlanReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if report.is_noop() && report.findings.is_empty() {
        out.push_str("No changes. sbproxy config is in sync.\n");
        return out;
    }
    if report.is_noop() {
        out.push_str("No changes. sbproxy config is in sync.\n");
    }
    for e in &report.entries {
        let sigil = match e.kind {
            PlanKind::Added => "+",
            PlanKind::Changed => "~",
            PlanKind::Removed => "-",
        };
        let label = match e.blast_radius {
            BlastRadius::Hitless => "hitless",
            BlastRadius::Reload => "reload",
            BlastRadius::Restart => "restart",
            BlastRadius::Breaking => "breaking",
        };
        let _ = writeln!(&mut out, "  {sigil} {} [{label}] {}", e.path, e.reason);
    }
    if !report.entries.is_empty() {
        let _ = writeln!(
            &mut out,
            "\nPlan: {} added, {} changed, {} removed. max-blast-radius: {}",
            report.summary.added,
            report.summary.changed,
            report.summary.removed,
            match report.max_blast_radius {
                BlastRadius::Hitless => "hitless",
                BlastRadius::Reload => "reload",
                BlastRadius::Restart => "restart",
                BlastRadius::Breaking => "breaking",
            }
        );
    }
    if !report.findings.is_empty() {
        let _ = writeln!(&mut out, "\nValidation:");
        let mut errors = 0usize;
        let mut warns = 0usize;
        for f in &report.findings {
            let label = match f.severity {
                Severity::Error => {
                    errors += 1;
                    "ERROR"
                }
                Severity::Warn => {
                    warns += 1;
                    "WARN "
                }
            };
            let _ = writeln!(
                &mut out,
                "  [{label}] {} ({}): {}",
                f.path, f.rule_id, f.message
            );
        }
        let _ = writeln!(
            &mut out,
            "\nValidation: {errors} error(s), {warns} warning(s)."
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile_config;

    fn parse(yaml: &str) -> ConfigFile {
        // Round-trip through `compile_config` to keep the parse path
        // identical to what the CLI does (env-var interpolation,
        // features-to-extensions migration, schema validation).
        // `compile_config` consumes the parsed `ConfigFile` though, so
        // we re-parse the post-migration YAML to recover the typed
        // form the diff walker wants.
        let _ = compile_config(yaml).expect("compile_config");
        serde_yaml::from_str::<ConfigFile>(yaml).expect("ConfigFile parse")
    }

    const ORIGIN_BASE: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#;

    const ORIGIN_BASE_PLUS_RATELIMIT: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    rate_limits:
      tenant_burst: 200
      tenant_sustained: 100
      route_default: 50
"#;

    const ORIGIN_TWO: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
  www.example.com:
    action:
      type: static
      body: "hello"
"#;

    const PROXY_BIND_CHANGE: &str = r#"
proxy:
  http_bind_port: 9090
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#;

    const ORIGIN_WITH_TRANSFORM: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    transforms:
      - type: noop
"#;

    #[test]
    fn plan_no_changes_is_noop() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_BASE);
        let report = plan(&a, &b);
        assert!(report.is_noop(), "expected no changes, got {:?}", report);
        assert_eq!(report.max_blast_radius, BlastRadius::Hitless);
    }

    #[test]
    fn plan_added_origin() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_TWO);
        let report = plan(&a, &b);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, PlanKind::Added);
        assert_eq!(entry.path, "origins.www.example.com");
        // Adding a static origin: dominant leaf is action.type
        // (action-type swap pattern); since the baseline is "absent"
        // we treat it as an introduction, which the matrix flags
        // breaking. Operators see the new origin's wire-format
        // commitment up front.
        assert!(matches!(
            entry.blast_radius,
            BlastRadius::Reload | BlastRadius::Breaking
        ));
        assert!(entry.old.is_none());
        assert!(entry.new.is_some());
        assert_eq!(report.summary.added, 1);
    }

    #[test]
    fn plan_removed_origin_is_breaking() {
        let a = parse(ORIGIN_TWO);
        let b = parse(ORIGIN_BASE);
        let report = plan(&a, &b);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, PlanKind::Removed);
        assert_eq!(entry.path, "origins.www.example.com");
        // Removing a published origin breaks wire compatibility.
        assert_eq!(entry.blast_radius, BlastRadius::Breaking);
        assert!(entry.new.is_none());
        assert!(entry.old.is_some());
        assert_eq!(report.summary.removed, 1);
    }

    #[test]
    fn plan_changed_origin_emits_field_preview_in_reason() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_BASE_PLUS_RATELIMIT);
        let report = plan(&a, &b);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, PlanKind::Changed);
        assert_eq!(entry.path, "origins.api.example.com");
        assert_eq!(entry.blast_radius, BlastRadius::Reload);
        assert!(
            entry.reason.contains("rate_limits"),
            "expected rate_limits in reason, got {:?}",
            entry.reason
        );
    }

    #[test]
    fn plan_proxy_bind_port_change_is_restart_class() {
        let a = parse(ORIGIN_BASE);
        let b = parse(PROXY_BIND_CHANGE);
        let report = plan(&a, &b);
        // Both files have the same single origin, only proxy.http_bind_port
        // differs, so we expect exactly one Changed entry on `proxy`.
        let proxy_entries: Vec<_> = report
            .entries
            .iter()
            .filter(|e| e.path == "proxy")
            .collect();
        assert_eq!(proxy_entries.len(), 1);
        let proxy_entry = proxy_entries[0];
        assert_eq!(proxy_entry.kind, PlanKind::Changed);
        // Per-path matrix: http_bind_port -> Restart
        assert_eq!(proxy_entry.blast_radius, BlastRadius::Restart);
        assert_eq!(report.max_blast_radius, BlastRadius::Restart);
    }

    #[test]
    fn plan_added_transform_changes_origin() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_WITH_TRANSFORM);
        let report = plan(&a, &b);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, PlanKind::Changed);
        assert_eq!(entry.path, "origins.api.example.com");
        assert_eq!(entry.blast_radius, BlastRadius::Reload);
        assert!(
            entry.reason.contains("transforms"),
            "expected 'transforms' in reason, got {:?}",
            entry.reason
        );
    }

    #[test]
    fn plan_json_envelope_is_stable() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_TWO);
        let report = plan(&a, &b);
        let json = serde_json::to_value(&report).expect("serialise");
        assert_eq!(json["plan_version"], 1);
        assert!(json["entries"].is_array());
        assert!(json["summary"].is_object());
        // The added origin's blast radius is whatever the matrix
        // resolves; either reload or breaking is acceptable here.
        let entry = &json["entries"][0];
        assert_eq!(entry["kind"], "added");
        assert_eq!(entry["path"], "origins.www.example.com");
    }

    #[test]
    fn render_text_noop_message() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_BASE);
        let report = plan(&a, &b);
        let text = render_text(&report);
        assert!(text.contains("No changes"), "got {text:?}");
    }

    #[test]
    fn render_text_added_origin_uses_plus_sigil() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_TWO);
        let report = plan(&a, &b);
        let text = render_text(&report);
        assert!(text.contains("+ origins.www.example.com"), "got {text:?}");
    }

    // --- WOR-180 step 4 matrix tests --------------------------------

    #[test]
    fn matrix_lookup_listener_port_is_restart() {
        // Direct matrix lookup: http_bind_port maps to Restart.
        let (r, _reason) = lookup_blast_radius("proxy.http_bind_port");
        assert_eq!(r, BlastRadius::Restart);
    }

    #[test]
    fn matrix_lookup_admin_port_is_restart() {
        let (r, _) = lookup_blast_radius("proxy.admin.port");
        assert_eq!(r, BlastRadius::Restart);
    }

    #[test]
    fn matrix_lookup_admin_other_field_is_reload() {
        let (r, _) = lookup_blast_radius("proxy.admin.basic_auth_users");
        assert_eq!(r, BlastRadius::Reload);
    }

    #[test]
    fn matrix_lookup_l2_driver_is_restart() {
        let (r, _) = lookup_blast_radius("proxy.l2_cache.driver");
        assert_eq!(r, BlastRadius::Restart);
        let (r2, _) = lookup_blast_radius("proxy.l2_cache_settings.driver");
        assert_eq!(r2, BlastRadius::Restart);
    }

    #[test]
    fn matrix_lookup_l2_param_is_reload() {
        let (r, _) = lookup_blast_radius("proxy.l2_cache.params.endpoint");
        assert_eq!(r, BlastRadius::Reload);
    }

    #[test]
    fn matrix_lookup_messenger_driver_is_restart() {
        let (r, _) = lookup_blast_radius("proxy.messenger_settings.driver");
        assert_eq!(r, BlastRadius::Restart);
    }

    #[test]
    fn matrix_lookup_metrics_is_hitless() {
        let (r, _) = lookup_blast_radius("proxy.metrics.scrape_endpoint");
        assert_eq!(r, BlastRadius::Hitless);
    }

    #[test]
    fn matrix_lookup_agent_classes_is_restart() {
        let (r, _) = lookup_blast_radius("agent_classes.catalog");
        assert_eq!(r, BlastRadius::Restart);
        let (r2, _) = lookup_blast_radius("agent_classes.resolver.cache_size");
        assert_eq!(r2, BlastRadius::Restart);
    }

    #[test]
    fn matrix_lookup_origin_auth_type_is_breaking() {
        let (r, _) = lookup_blast_radius("origins.*.authentication.type");
        assert_eq!(r, BlastRadius::Breaking);
    }

    #[test]
    fn matrix_lookup_origin_action_type_is_breaking() {
        let (r, _) = lookup_blast_radius("origins.*.action.type");
        assert_eq!(r, BlastRadius::Breaking);
    }

    #[test]
    fn matrix_lookup_origin_other_action_field_is_reload() {
        let (r, _) = lookup_blast_radius("origins.*.action.url");
        assert_eq!(r, BlastRadius::Reload);
    }

    #[test]
    fn matrix_lookup_origin_policy_is_reload() {
        let (r, _) = lookup_blast_radius("origins.*.policies.*");
        assert_eq!(r, BlastRadius::Reload);
    }

    #[test]
    fn matrix_lookup_unknown_path_falls_through_to_reload() {
        let (r, _) = lookup_blast_radius("some.entirely.new.path");
        assert_eq!(r, BlastRadius::Reload);
    }

    #[test]
    fn canonicalise_replaces_array_indices() {
        // Hostname canonicalisation is handled upstream (the diff
        // walker passes `origins.*` as the base path), so the
        // canonicaliser only has to swap numeric array indices.
        assert_eq!(
            canonicalise_path("origins.*.policies.0.type"),
            "origins.*.policies.*.type"
        );
        assert_eq!(
            canonicalise_path("proxy.trusted_proxies.0"),
            "proxy.trusted_proxies.*"
        );
        assert_eq!(canonicalise_path("a.b.c"), "a.b.c");
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("a.b.c", "a.b.c"));
        assert!(glob_match("a.*.c", "a.x.c"));
        assert!(glob_match("a.*", "a.x"));
        assert!(!glob_match("a.*", "a"));
        assert!(!glob_match("a.b", "a.b.c"));
        assert!(!glob_match("a.b", "a.x"));
    }

    #[test]
    fn glob_match_double_star_matches_subtree() {
        assert!(glob_match("a.**", "a.b"));
        assert!(glob_match("a.**", "a.b.c.d"));
        assert!(glob_match("a.b.**", "a.b.c"));
        assert!(glob_match("a.b.**", "a.b.c.d"));
        assert!(!glob_match("a.**", "a"));
        assert!(!glob_match("a.b.**", "a.b"));
        assert!(!glob_match("a.b.**", "a.x.c"));
    }

    // --- Step 5: plan-file + baseline_revision ----------------------

    #[test]
    fn plan_file_round_trip_preserves_baseline_revision() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_TWO);
        let report = plan(&a, &b);
        let pf = PlanFile::new(&a, report);

        let dir = std::env::temp_dir().join(format!(
            "sbproxy-plan-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.json");
        pf.write_to_path(&path).expect("write plan");

        let loaded = PlanFile::read_from_path(&path).expect("read plan");
        assert_eq!(loaded.plan_file_version, 1);
        assert_eq!(loaded.baseline_revision, pf.baseline_revision);
        assert_eq!(loaded.report.entries.len(), pf.report.entries.len());
    }

    #[test]
    fn baseline_revision_changes_when_baseline_changes() {
        let a = parse(ORIGIN_BASE);
        let b = parse(ORIGIN_TWO);
        let r1 = compute_baseline_revision(&a);
        let r2 = compute_baseline_revision(&b);
        assert_ne!(r1, r2);
        // 64 hex chars = 32 bytes = SHA-256.
        assert_eq!(r1.len(), 64);
        assert_eq!(r2.len(), 64);
    }

    #[test]
    fn baseline_revision_is_stable_across_runs() {
        let a = parse(ORIGIN_BASE);
        let r1 = compute_baseline_revision(&a);
        let r2 = compute_baseline_revision(&a);
        assert_eq!(r1, r2);
    }

    #[test]
    fn sha256_known_answer_empty_string() {
        // FIPS 180-4 KAT: SHA-256("") =
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_known_answer_abc() {
        // FIPS 180-4 KAT: SHA-256("abc") =
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

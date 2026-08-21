// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Lowering `proxy.attestation` into something the request path can run.
//!
//! The config surface and the metering vocabulary are deliberately in
//! two different crates that do not know about each other.
//! `sbproxy-config` owns the YAML shape and derives a JSON Schema over
//! it; `sbproxy-meter` owns [`sbproxy_meter::OutcomeTable`] and depends
//! on no other crate in this workspace, so an operator metering a plain
//! REST API can compile it without the gateway. Putting a schema derive
//! on the meter's types would end that property quietly, so the
//! translation lives here instead, in the one crate that already
//! depends on both.
//!
//! # The table is where the honesty is
//!
//! [`sbproxy_meter::OutcomeTable`] refuses to exist until every
//! [`sbproxy_meter::BillableOutcome`] has an explicit answer, and this
//! module does not soften that. `proxy.attestation.billable` accepts eight optional
//! keys purely so an incomplete block can be reported as one error
//! naming every missing outcome, rather than as eight successive serde
//! failures naming one field each. Nothing is defaulted on the way
//! through: an unstated billing rule still runs, it just runs as
//! whatever the code happened to do, and nobody finds out what that was
//! until a buyer asks.
//!
//! # The resolvers are lowered, never merged
//!
//! `proxy.attestation.measured`, `proxy.attestation.route_weights`, and
//! `proxy.attestation.origin_headers` become three independent
//! collections on [`crate::attestation::AttestationRuntime`], and they
//! stay independent. A route matched by more than one contributes one
//! entry to a receipt's units per source, because the sources have
//! different provenance and summing them produces a number whose parts
//! can no longer be checked separately. See [`sbproxy_meter`].
//!
//! # Validation mode never touches the disk
//!
//! `prepare_attestation` creates the directory the ledger lives in and
//! opens the receipt chain. Those are real side effects and exactly the
//! reason the pipeline calls it only under
//! `PipelineConstructionMode::Runtime`. `sbproxy validate` must be able
//! to check a candidate config on an operator's laptop without leaving
//! ledger files behind. Everything that can be decided without a
//! filesystem is decided earlier, at config compile, so validation still
//! rejects a broken block.
//!
//! The ledger is the whole of that list. WOR-2623: boot used to create
//! the claim queue's directory too, on the same "find out at boot that
//! the disk is unwritable" reasoning, and that reasoning belonged to a
//! half of attestation this build does not have. `compile_config`
//! refuses every role that makes claims, so no code path can ever put a
//! byte in that directory, and a directory nothing writes is a mark on
//! an operator's disk they have to explain. It is left alone until the
//! claim lifecycle lands with something to write there.
//!
//! Opening the chain is the one side effect that cannot fail the boot.
//! A ledger that will not open becomes an unwritable
//! [`crate::meter_runtime::ReceiptChain`] and
//! [`crate::attestation::AttestationRuntime::failure_mode`] decides what
//! happens to traffic, because a full disk taking the API down is
//! precisely the outcome the `degraded` default exists to prevent.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sbproxy_config::types::{
    AttestationBillableConfig, AttestationConfig, AttestationLedgerConfig,
    AttestationMeasuredConfig, AttestationMeasuredQuantity, AttestationOriginHeaderConfig,
    AttestationQueueConfig, AttestationRole, AttestationRouteWeightConfig, BillableRule,
    EnforcementMode, FailureMode, OriginAttestationConfig, WebBotAuthConfig,
    ATTESTATION_SIGN_WITH_WEB_BOT_AUTH,
};
use sbproxy_meter::{
    Billable, BillableOutcome, MeasuredQuantity, MeasuredRule, OriginHeaderRule, OutcomeTable,
    RouteWeightRule, RouteWeightTable,
};

/// The attestation posture one pipeline generation runs under.
///
/// Built once when a config is compiled and then immutable, so the
/// request path never re-reads YAML and a reload swaps the whole object
/// rather than mutating it underneath in-flight requests.
///
/// `Debug` is derived rather than hand-written because nothing at this
/// level is secret. `signing_key_id` is the `kid` that gets published in
/// the JWKS, and the rest is paths, counts, and postures. The seed is
/// held one level down, inside
/// [`crate::meter_runtime::ReceiptChain`], which carries a hand-written
/// [`std::fmt::Debug`] that prints only the kid, the way the receipt and
/// quote signers do. Should anything secret ever land on this struct
/// directly, replace the derive rather than trusting the field below to
/// keep containing it.
#[derive(Debug)]
pub struct AttestationRuntime {
    /// Which halves of attestation this proxy performs proxy-wide.
    /// Origins may narrow or widen it; see
    /// [`ResolvedOriginAttestation`].
    pub role: AttestationRole,
    /// What to do when attestation itself cannot run. Defaults to
    /// [`FailureMode::Degraded`] rather than the surface-wide `closed`,
    /// because billing is not a security boundary and a full ledger disk
    /// should not take the API down. The `degraded` posture is what
    /// keeps the resulting hole provable: the call proceeds, the
    /// guarantee is marked as not made, and the gap is countable.
    pub failure_mode: FailureMode,
    /// What to do when attestation reaches a verdict of "refuse".
    /// Separate from [`Self::failure_mode`] on purpose: a control can
    /// reasonably observe while it is being tuned and still need to fail
    /// closed when its backend disappears.
    pub enforcement_mode: EnforcementMode,
    /// Key id that signs receipts, resolved from the identity
    /// `proxy.attestation.sign_with` names. `None` when the role makes
    /// claims but writes no receipts.
    pub signing_key_id: Option<String>,
    /// Where unsettled claims would be held.
    ///
    /// Resolved and recorded, and read by nothing. WOR-2623: the claim
    /// half of attestation is not implemented in this build and
    /// `compile_config` refuses every role that asks for it, so no
    /// claim is ever written here and boot does not create the
    /// directory either. Kept resolved rather than dropped so the
    /// lifecycle slice lands against a path already lowered the same
    /// way the ledger's is.
    pub queue_path: PathBuf,
    /// How many unsettled claims would be held before
    /// [`Self::failure_mode`] applies. Read by nothing today, for the
    /// reason [`Self::queue_path`] gives.
    pub queue_max_entries: usize,
    /// Where settled records are chained.
    pub ledger_path: PathBuf,
    /// The operator's complete position on what they charge for.
    pub outcomes: OutcomeTable,
    /// Units this generation counts for itself.
    ///
    /// Listed first because it is the resolver with nothing outside the
    /// process in it: the proxy saw the bytes and held the clock, so
    /// nobody else contributed to the number. A receipt is easier to
    /// argue about when an unarguable line is sitting next to the
    /// contested ones.
    pub measured: Vec<MeasuredRule>,
    /// Routes this generation prices, bound to the revision that priced
    /// them.
    ///
    /// Holding the table here rather than looking weights up against
    /// whatever config is live when a unit is written is what keeps a
    /// reload from repricing a call already in flight. A request holds
    /// the generation that admitted it until it finishes, and the
    /// revision on the receipt is therefore the revision that actually
    /// decided the price.
    pub route_weights: RouteWeightTable,
    /// Counts this generation reads back from upstream responses.
    ///
    /// The one source that can be wrong without the proxy being wrong,
    /// which is why the resolver attests to what arrived rather than
    /// vouching for it. See `sbproxy_meter::origin_header`.
    pub origin_headers: Vec<OriginHeaderRule>,
    /// This node's receipt chain, opened once per generation.
    ///
    /// `None` when the role writes no receipts, which is every posture
    /// that only makes claims. `Some` with an unwritable chain inside is
    /// a different statement and a deliberate one: the ledger could not
    /// be opened, and [`Self::failure_mode`] rather than a boot failure
    /// decides what happens to traffic. See
    /// `crate::meter_runtime::ReceiptChain::open`.
    pub chain: Option<Arc<crate::meter_runtime::ReceiptChain>>,
}

/// The attestation posture one origin runs under, after the proxy-wide
/// block and the origin's override have been composed.
///
/// Resolved once per pipeline generation and held in a vector parallel
/// to the compiled origins, so the request path indexes rather than
/// looks up, and never re-composes precedence per request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOriginAttestation {
    /// The role in force for this origin: its own when it declared one,
    /// otherwise the proxy-wide role.
    pub role: AttestationRole,
    /// The commercial agreement this origin's units are billed under.
    /// `None` means receipts for this origin record consumption without
    /// naming the contract that prices it.
    pub agreement_id: Option<String>,
}

/// Build the runtime attestation object from `proxy.attestation`.
///
/// Returns `Ok(None)` when the block is absent or its role is
/// [`AttestationRole::Off`], which is every config that does not opt in.
///
/// `config_revision` is the revision of the document being lowered, and
/// it is a parameter rather than something read from a global on
/// purpose. Every route weight this generation produces will cite it,
/// and a receipt citing a revision other than the one that supplied the
/// weight is worse than a receipt with no evidence at all, because it
/// reads as proof.
///
/// The queue and ledger directories are created here, and a role that
/// writes receipts also opens its chain here. Those are the side effects
/// the caller gates on construction mode; see the module docs. Opening
/// the chain cannot fail: a ledger that will not open is a runtime
/// condition that [`AttestationRuntime::failure_mode`] answers, not a
/// reason to refuse to boot.
///
/// `node_id` is the identity the chain's entries are attributed to, and
/// it has to be the same id the mesh gather keys segments by, or this
/// node's chain is one nobody can attribute. It is a parameter for the
/// same reason `config_revision` is: reading it from a global here would
/// let a generation be built against one identity and report under
/// another.
///
/// # Errors
///
/// Returns an error when a declared role has no queue, no ledger, or an
/// incomplete billing table, when `sign_with` names an identity this
/// build cannot resolve, when a receipt-writing role resolves no signing
/// identity at all, or when a state directory cannot be created.
/// `compile_config` rejects all of those earlier, so reaching them here
/// means a pipeline was built from something other than a compiled
/// config; the checks stay because a runtime that assumes its input was
/// validated elsewhere is a runtime that panics when it was not.
pub(crate) fn prepare_attestation(
    cfg: Option<&AttestationConfig>,
    web_bot_auth: Option<&WebBotAuthConfig>,
    config_revision: &str,
    node_id: &str,
) -> Result<Option<Arc<AttestationRuntime>>> {
    let attestation: &AttestationConfig = match cfg {
        Some(attestation) => attestation,
        None => return Ok(None),
    };

    let role: AttestationRole = attestation.role;
    if !role.makes_claims() && !role.writes_receipts() {
        return Ok(None);
    }
    let failure_mode: FailureMode = attestation.failure_mode;
    let enforcement_mode: EnforcementMode = attestation.enforcement_mode;

    let signing_key_id: Option<String> = match attestation.sign_with.as_deref() {
        None => None,
        Some(identity) if identity == ATTESTATION_SIGN_WITH_WEB_BOT_AUTH => {
            let signer: &WebBotAuthConfig = match web_bot_auth {
                Some(signer) => signer,
                None => anyhow::bail!(
                    "proxy.attestation.sign_with names `{ATTESTATION_SIGN_WITH_WEB_BOT_AUTH}`, \
                     but that block is not configured"
                ),
            };
            Some(signer.key_id.clone())
        }
        Some(other) => anyhow::bail!(
            "proxy.attestation.sign_with `{other}` is not a signing identity this build can \
             resolve; the only accepted value is `{ATTESTATION_SIGN_WITH_WEB_BOT_AUTH}`"
        ),
    };

    let (queue_path, queue_max_entries) = match &attestation.queue {
        Some(queue) => queue_location(queue),
        None => anyhow::bail!(
            "proxy.attestation declares a role but no queue, so a restart would drop every \
             claim in flight"
        ),
    };

    let ledger_path = match &attestation.ledger {
        Some(ledger) => ledger_location(ledger),
        None => anyhow::bail!(
            "proxy.attestation declares a role but no ledger, so a missing record would be \
             indistinguishable from a call that never happened"
        ),
    };

    let outcomes: OutcomeTable = match &attestation.billable {
        Some(billable) => outcome_table(billable)?,
        None => anyhow::bail!(
            "proxy.attestation declares a role but no billable table, and there is no \
             default for what an operator charges for"
        ),
    };

    let measured: Vec<MeasuredRule> = attestation.measured.iter().map(measured_rule).collect();
    let route_weights: RouteWeightTable = RouteWeightTable::new(
        config_revision,
        attestation
            .route_weights
            .iter()
            .map(route_weight_rule)
            .collect(),
    );
    let origin_headers: Vec<OriginHeaderRule> = attestation
        .origin_headers
        .iter()
        .map(origin_header_rule)
        .collect();

    // Boot is the right time to find out the state directory is
    // unwritable. Discovering it at the first receipt means the first
    // billable request of the deployment is also the first one that
    // takes the failure_mode branch.
    //
    // The ledger only. WOR-2623: the queue directory was created here
    // too, and nothing has ever written to it. `compile_config` refuses
    // every role that makes claims, so nothing can, and creating a
    // directory for a file this build will not produce leaves an
    // operator holding state they cannot account for.
    ensure_state_dir(&ledger_path, "proxy.attestation.ledger.path")?;

    // The chain is opened here, once, and pinned to this generation, so a
    // request that started under one configuration keeps writing to the
    // chain that configuration opened. Only a role that writes receipts
    // gets one: a proxy that only makes claims has nothing to chain, and
    // opening a ledger it will never write to would create a file an
    // operator then has to explain.
    let chain: Option<Arc<crate::meter_runtime::ReceiptChain>> = match (
        role.writes_receipts(),
        signing_key_id.as_deref(),
        web_bot_auth,
    ) {
        (false, _, _) => None,
        (true, Some(key_id), Some(signer)) => {
            Some(Arc::new(crate::meter_runtime::ReceiptChain::open(
                &ledger_path,
                &signer.ed25519_seed_hex,
                key_id,
                node_id,
            )))
        }
        (true, _, _) => anyhow::bail!(
            "proxy.attestation.role writes receipts but no signing identity resolved, so every \
             receipt would be an unsigned log line"
        ),
    };

    Ok(Some(Arc::new(AttestationRuntime {
        role,
        failure_mode,
        enforcement_mode,
        signing_key_id,
        queue_path,
        queue_max_entries,
        ledger_path,
        outcomes,
        measured,
        route_weights,
        origin_headers,
        chain,
    })))
}

/// Lower one configured measured unit into the meter's rule.
///
/// The quantity is matched exhaustively with no wildcard arm, the same
/// way `meter_billable` is, because the two enums are two vocabularies
/// that must agree and this is the only place they meet. Adding a
/// quantity on either side stops the build here rather than silently
/// metering the new one as whatever the wildcard happened to pick.
fn measured_rule(entry: &AttestationMeasuredConfig) -> MeasuredRule {
    let quantity: MeasuredQuantity = match entry.quantity {
        AttestationMeasuredQuantity::Requests => MeasuredQuantity::Requests,
        AttestationMeasuredQuantity::BytesIn => MeasuredQuantity::BytesIn,
        AttestationMeasuredQuantity::BytesOut => MeasuredQuantity::BytesOut,
        AttestationMeasuredQuantity::DurationMs => MeasuredQuantity::DurationMs,
    };
    // `per` is a plain `u64` in config and a `NonZeroU64` here, so the
    // zero has to go somewhere. `compile_config` rejects it, which makes
    // this fallback unreachable through the supported path, and it is a
    // fallback rather than an `expect` for the same reason the bails
    // above are checks rather than assumptions: this is a runtime, and a
    // runtime that panics on input it was told had been validated is a
    // runtime that takes the process down over somebody else's bug.
    // Billing one unit per observed item is the reading an operator who
    // omitted the key would have got anyway.
    let per: NonZeroU64 = NonZeroU64::new(entry.per).unwrap_or(NonZeroU64::MIN);
    MeasuredRule::new(entry.name.clone(), quantity, per)
}

/// Lower one configured route weight into the meter's rule.
///
/// Every field is copied across explicitly. The config vocabulary and
/// the metering vocabulary are two types on purpose (see the module
/// docs), and this is the seam, so a field added on either side has to
/// be dealt with here rather than silently dropped on the way to a
/// receipt.
fn route_weight_rule(entry: &AttestationRouteWeightConfig) -> RouteWeightRule {
    RouteWeightRule {
        name: entry.name.clone(),
        method: entry.method.clone(),
        path: entry.path.clone(),
        weight: entry.weight,
    }
}

/// Lower one configured origin-header rule into the meter's rule.
fn origin_header_rule(entry: &AttestationOriginHeaderConfig) -> OriginHeaderRule {
    OriginHeaderRule {
        name: entry.name.clone(),
        header: entry.header.clone(),
    }
}

/// Compose the proxy-wide role with one origin's override.
///
/// Precedence is the ordinary one: an explicit origin role wins, an
/// absent one inherits. `agreement_id` has no proxy-wide counterpart to
/// compose with, because which contract prices a call is a property of
/// who is on the other end of it and never of the proxy.
pub(crate) fn resolve_origin_attestation(
    proxy: Option<&AttestationConfig>,
    origin: Option<&OriginAttestationConfig>,
) -> ResolvedOriginAttestation {
    let proxy_role: AttestationRole = match proxy {
        Some(proxy) => proxy.role,
        None => AttestationRole::Off,
    };
    let (role, agreement_id) = match origin {
        Some(origin) => (
            origin.role.unwrap_or(proxy_role),
            origin.agreement_id.clone(),
        ),
        None => (proxy_role, None),
    };
    ResolvedOriginAttestation { role, agreement_id }
}

/// Where the claim queue lives, and how much of it there is.
fn queue_location(queue: &AttestationQueueConfig) -> (PathBuf, usize) {
    (PathBuf::from(queue.path.as_str()), queue.max_entries)
}

/// Where the settled-record chain lives.
fn ledger_location(ledger: &AttestationLedgerConfig) -> PathBuf {
    PathBuf::from(ledger.path.as_str())
}

/// Turn the configured billing answers into the meter crate's table.
///
/// The missing-outcome check runs first so the operator gets the whole
/// list in one message. [`OutcomeTable::from_entries`] would reject an
/// incomplete set on its own, and does, but only after this crate has
/// already had the chance to say it in the vocabulary of the config file
/// the operator is editing.
fn outcome_table(billable: &AttestationBillableConfig) -> Result<OutcomeTable> {
    let missing: Vec<&'static str> = billable.missing_outcomes();
    if !missing.is_empty() {
        anyhow::bail!(
            "proxy.attestation.billable has no answer for {}; every outcome needs one, \
             because a billing rule left implicit is a billing rule nobody agreed to",
            missing.join(", "),
        );
    }

    // Exhaustive by construction: `BillableOutcome::ALL` is what
    // `from_entries` checks against, so adding an outcome to the meter
    // crate makes this list short and fails the build here rather than
    // silently billing the new case as whatever `None` meant.
    let configured: [(BillableOutcome, Option<BillableRule>); 8] = [
        (BillableOutcome::Delivered, billable.delivered),
        (
            BillableOutcome::ClientDisconnected,
            billable.client_disconnected,
        ),
        (BillableOutcome::Origin4xx, billable.origin_4xx),
        (BillableOutcome::Origin5xx, billable.origin_5xx),
        (BillableOutcome::PolicyBlocked, billable.policy_blocked),
        (BillableOutcome::RateLimited, billable.rate_limited),
        (BillableOutcome::CacheHit, billable.cache_hit),
        (BillableOutcome::Retry, billable.retry),
    ];

    let entries: Vec<(BillableOutcome, Billable)> = configured
        .into_iter()
        .filter_map(|(outcome, rule)| rule.map(|rule| (outcome, meter_billable(rule))))
        .collect();

    OutcomeTable::from_entries(&entries)
        .map_err(|error| anyhow::anyhow!("proxy.attestation.billable: {error}"))
}

/// Translate one config answer into the meter crate's answer.
///
/// Written as an exhaustive match with no wildcard arm so that adding a
/// fifth billing answer on either side stops the build here, which is
/// the only place the two vocabularies meet.
fn meter_billable(rule: BillableRule) -> Billable {
    match rule {
        BillableRule::Yes => Billable::Yes,
        BillableRule::No => Billable::No,
        BillableRule::Partial => Billable::Partial,
        BillableRule::Collapse => Billable::Collapse,
    }
}

/// Create the directory a state file lives in, if it does not exist.
///
/// A bare filename with no directory component is left alone: it names a
/// file in the working directory, and there is nothing to create.
fn ensure_state_dir(path: &Path, key: &str) -> Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => return Ok(()),
    };
    std::fs::create_dir_all(parent)
        .with_context(|| format!("{key}: creating state directory {}", parent.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_meter::{Evidence, UnitSource};

    /// The revision every test lowers under, standing in for the one the
    /// pipeline computes over the serialized document.
    const REVISION: &str = "9f2c41a0be77";

    /// The node every test chain is attributed to.
    const NODE: &str = "node-a";

    fn complete_billable() -> AttestationBillableConfig {
        AttestationBillableConfig {
            delivered: Some(BillableRule::Yes),
            client_disconnected: Some(BillableRule::Partial),
            origin_4xx: Some(BillableRule::No),
            origin_5xx: Some(BillableRule::No),
            policy_blocked: Some(BillableRule::No),
            rate_limited: Some(BillableRule::No),
            cache_hit: Some(BillableRule::Yes),
            retry: Some(BillableRule::Collapse),
        }
    }

    #[test]
    fn every_config_answer_maps_to_the_meter_answer_it_names() {
        let table = outcome_table(&complete_billable()).expect("a complete table builds");

        assert_eq!(table.billable(BillableOutcome::Delivered), Billable::Yes);
        assert_eq!(
            table.billable(BillableOutcome::ClientDisconnected),
            Billable::Partial
        );
        assert_eq!(table.billable(BillableOutcome::Origin5xx), Billable::No);
        assert_eq!(table.billable(BillableOutcome::CacheHit), Billable::Yes);
        assert_eq!(table.billable(BillableOutcome::Retry), Billable::Collapse);
    }

    #[test]
    fn an_incomplete_table_names_every_outcome_it_is_missing_at_once() {
        let mut billable = complete_billable();
        billable.cache_hit = None;
        billable.origin_4xx = None;

        let error = outcome_table(&billable).expect_err("an incomplete table is not a table");
        let rendered = error.to_string();

        assert!(rendered.contains("origin_4xx"), "{rendered}");
        assert!(rendered.contains("cache_hit"), "{rendered}");
    }

    #[test]
    fn an_absent_or_off_block_builds_no_runtime() {
        assert!(prepare_attestation(None, None, REVISION, NODE)
            .expect("absent block is not an error")
            .is_none());

        let off = AttestationConfig::default();
        assert_eq!(off.role, AttestationRole::Off);
        assert!(prepare_attestation(Some(&off), None, REVISION, NODE)
            .expect("an off role is not an error")
            .is_none());
    }

    #[test]
    fn the_default_failure_mode_departs_from_the_surface_wide_closed() {
        // Billing is not a security boundary. A full ledger disk taking
        // the API down is worse than a provable hole in the record.
        assert_eq!(
            AttestationConfig::default().failure_mode,
            FailureMode::Degraded
        );
        assert!(AttestationConfig::default().failure_mode.admits());
        assert!(AttestationConfig::default().failure_mode.guarantee_waived());
    }

    #[test]
    fn an_origin_role_override_wins_over_the_proxy_role() {
        // Narrowing, because that is the only direction a supported
        // config can override in: `compile_config` refuses every role
        // that makes claims, at the proxy and at the origin alike.
        let proxy = AttestationConfig {
            role: AttestationRole::Receipt,
            ..AttestationConfig::default()
        };
        let origin = OriginAttestationConfig {
            role: Some(AttestationRole::Off),
            agreement_id: Some("acme-2026".to_string()),
        };

        let resolved = resolve_origin_attestation(Some(&proxy), Some(&origin));

        assert_eq!(resolved.role, AttestationRole::Off);
        assert_eq!(resolved.agreement_id.as_deref(), Some("acme-2026"));
    }

    #[test]
    fn an_origin_without_an_override_inherits_the_proxy_role() {
        let proxy = AttestationConfig {
            role: AttestationRole::Receipt,
            ..AttestationConfig::default()
        };

        let inherited = resolve_origin_attestation(Some(&proxy), None);
        assert_eq!(inherited.role, AttestationRole::Receipt);
        assert!(inherited.agreement_id.is_none());

        let agreement_only = resolve_origin_attestation(
            Some(&proxy),
            Some(&OriginAttestationConfig {
                role: None,
                agreement_id: Some("acme-2026".to_string()),
            }),
        );
        assert_eq!(agreement_only.role, AttestationRole::Receipt);
        assert_eq!(agreement_only.agreement_id.as_deref(), Some("acme-2026"));
    }

    #[test]
    fn no_proxy_block_leaves_every_origin_off() {
        let resolved = resolve_origin_attestation(None, None);
        assert_eq!(resolved.role, AttestationRole::Off);
    }

    #[test]
    fn a_runtime_role_resolves_its_paths_and_signing_identity() {
        let dir = tempfile::tempdir().expect("temp dir");
        let queue_path = dir.path().join("state").join("claims.q");
        let ledger_path = dir.path().join("state").join("receipts.ndjson");

        let cfg = AttestationConfig {
            role: AttestationRole::Receipt,
            sign_with: Some(ATTESTATION_SIGN_WITH_WEB_BOT_AUTH.to_string()),
            queue: Some(AttestationQueueConfig {
                path: queue_path.display().to_string(),
                max_entries: 4_096,
            }),
            ledger: Some(AttestationLedgerConfig {
                path: ledger_path.display().to_string(),
            }),
            billable: Some(complete_billable()),
            ..AttestationConfig::default()
        };
        let signer = WebBotAuthConfig {
            key_id: "sbproxy-2026".to_string(),
            ed25519_seed_hex: "0".repeat(64),
            directory_url: None,
        };

        let runtime = prepare_attestation(Some(&cfg), Some(&signer), REVISION, NODE)
            .expect("a complete block builds")
            .expect("a declared role yields a runtime");

        assert_eq!(runtime.role, AttestationRole::Receipt);
        assert_eq!(runtime.signing_key_id.as_deref(), Some("sbproxy-2026"));
        assert_eq!(runtime.queue_max_entries, 4_096);
        assert_eq!(runtime.queue_path, queue_path);
        assert_eq!(runtime.ledger_path, ledger_path);
        assert_eq!(
            runtime.outcomes.billable(BillableOutcome::Retry),
            Billable::Collapse
        );
        assert!(
            ledger_path
                .parent()
                .expect("the ledger has a parent")
                .is_dir(),
            "boot creates the state directory so the first receipt is not the first failure"
        );
        let chain = runtime
            .chain
            .as_deref()
            .expect("a role that writes receipts opens a chain");
        assert!(chain.is_writable());
        assert_eq!(chain.node_id(), NODE);
    }

    /// `compile_config` refuses every claim-making role (WOR-2623), so
    /// this is not a config a supported path can reach. The arm stays,
    /// and so does this test, for the same reason the bails above are
    /// checks rather than assumptions: a runtime that assumes its input
    /// came from a compiled config is a runtime that misbehaves when it
    /// did not.
    #[test]
    fn a_role_that_makes_claims_and_writes_none_opens_no_chain() {
        // Opening a ledger the role will never write to would leave a file
        // an operator then has to explain.
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = AttestationConfig {
            role: AttestationRole::Claim,
            ..metering_config(dir.path(), Vec::new(), Vec::new())
        };

        let runtime = prepare_attestation(Some(&cfg), Some(&signer()), REVISION, NODE)
            .expect("a complete block builds")
            .expect("a declared role yields a runtime");

        assert!(runtime.chain.is_none());
        assert!(!runtime.ledger_path.exists());
    }

    /// WOR-2623: boot creates the ledger's directory, because the chain
    /// is opened there and appended to. It creates nothing for the
    /// queue. No claim is written anywhere in this build, so a directory
    /// for one is state an operator carries and nobody can account for,
    /// and the two paths are deliberately in different directories here
    /// so the ledger's own `create_dir_all` cannot cover for the queue's.
    #[test]
    fn boot_creates_the_ledger_directory_and_leaves_no_queue_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let queue_dir = dir.path().join("queue");
        let ledger_dir = dir.path().join("ledger");
        let cfg = AttestationConfig {
            queue: Some(AttestationQueueConfig {
                path: queue_dir.join("claims.q").display().to_string(),
                max_entries: 16,
            }),
            ledger: Some(AttestationLedgerConfig {
                path: ledger_dir.join("receipts.ndjson").display().to_string(),
            }),
            ..metering_config(dir.path(), Vec::new(), Vec::new())
        };

        let runtime = prepare_attestation(Some(&cfg), Some(&signer()), REVISION, NODE)
            .expect("a complete block builds")
            .expect("a receipt role yields a runtime");

        assert!(
            runtime.chain.is_some(),
            "a receipt role opens its chain, which is what makes the ledger directory needed"
        );
        assert!(
            ledger_dir.is_dir(),
            "the chain is opened under {}, so boot has to create it",
            ledger_dir.display()
        );
        assert!(
            !queue_dir.exists(),
            "nothing writes the claim queue, so nothing creates {}",
            queue_dir.display()
        );
    }

    #[test]
    fn a_receipt_role_without_its_named_signer_fails_loud() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = metering_config(dir.path(), Vec::new(), Vec::new());
        assert_eq!(
            cfg.sign_with.as_deref(),
            Some(ATTESTATION_SIGN_WITH_WEB_BOT_AUTH)
        );

        let error = prepare_attestation(Some(&cfg), None, REVISION, NODE)
            .expect_err("a receipt with nothing to sign it is not a receipt");
        assert!(
            error.to_string().contains("sign_with"),
            "the error names the key the operator has to fix: {error}"
        );
    }

    #[test]
    fn a_receipt_role_with_no_signing_identity_at_all_fails_loud() {
        // `compile_config` rejects this earlier, so reaching it means a
        // pipeline was built from something other than a compiled config.
        // The check stays because an unsigned receipt is a log line.
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = AttestationConfig {
            sign_with: None,
            ..metering_config(dir.path(), Vec::new(), Vec::new())
        };

        let error = prepare_attestation(Some(&cfg), Some(&signer()), REVISION, NODE)
            .expect_err("a receipt nobody signed is not a receipt");
        assert!(error.to_string().contains("signing identity"), "{error}");
    }

    /// A complete block with whatever resolvers a test wants on it, with
    /// its state under `dir`.
    ///
    /// The paths are absolute on purpose. A receipt role opens its chain
    /// during lowering, so a relative path here would leave a ledger file
    /// in whatever directory the test runner happened to start in.
    fn metering_config(
        dir: &Path,
        route_weights: Vec<AttestationRouteWeightConfig>,
        origin_headers: Vec<AttestationOriginHeaderConfig>,
    ) -> AttestationConfig {
        AttestationConfig {
            role: AttestationRole::Receipt,
            sign_with: Some(ATTESTATION_SIGN_WITH_WEB_BOT_AUTH.to_string()),
            queue: Some(AttestationQueueConfig {
                path: dir.join("claims.q").display().to_string(),
                max_entries: 16,
            }),
            ledger: Some(AttestationLedgerConfig {
                path: dir.join("receipts.ndjson").display().to_string(),
            }),
            billable: Some(complete_billable()),
            route_weights,
            origin_headers,
            ..AttestationConfig::default()
        }
    }

    fn signer() -> WebBotAuthConfig {
        WebBotAuthConfig {
            key_id: "sbproxy-2026".to_string(),
            ed25519_seed_hex: "0".repeat(64),
            directory_url: None,
        }
    }

    #[test]
    fn declared_resolvers_lower_into_the_metering_vocabulary() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = metering_config(
            dir.path(),
            vec![AttestationRouteWeightConfig {
                name: "search_call".to_string(),
                method: Some("POST".to_string()),
                path: "/v1/search".to_string(),
                weight: 5,
            }],
            vec![AttestationOriginHeaderConfig {
                name: "result_row".to_string(),
                header: "X-Rows-Returned".to_string(),
            }],
        );

        let runtime = prepare_attestation(Some(&cfg), Some(&signer()), REVISION, NODE)
            .expect("a complete block builds")
            .expect("a declared role yields a runtime");

        let weights = runtime.route_weights.resolve("POST", "/v1/search");
        assert_eq!(weights.len(), 1);
        assert_eq!(weights[0].name, "search_call");
        assert_eq!(weights[0].count, 5);
        assert_eq!(weights[0].source, UnitSource::RouteWeight);

        assert_eq!(runtime.origin_headers.len(), 1);
        let claimed = runtime.origin_headers[0].resolve(Some("47"));
        assert_eq!(claimed.unit.name, "result_row");
        assert_eq!(claimed.unit.count, 47);
        assert_eq!(claimed.unit.source, UnitSource::OriginHeader);
    }

    #[test]
    fn route_weights_cite_the_revision_this_generation_was_built_from() {
        // The pairing this parameter exists to make impossible: weights
        // from one document citing the revision of another. A generation
        // gets its revision when it is built, so an in-flight request
        // holding an older runtime keeps the older tag.
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = metering_config(
            dir.path(),
            vec![AttestationRouteWeightConfig {
                name: "search_call".to_string(),
                method: None,
                path: "/v1/search".to_string(),
                weight: 5,
            }],
            Vec::new(),
        );

        let old = prepare_attestation(Some(&cfg), Some(&signer()), REVISION, NODE)
            .expect("builds")
            .expect("a declared role yields a runtime");
        let new = prepare_attestation(Some(&cfg), Some(&signer()), "0011223344ff", NODE)
            .expect("builds")
            .expect("a declared role yields a runtime");

        assert_eq!(
            old.route_weights.resolve("POST", "/v1/search")[0].evidence,
            Evidence::RouteWeight {
                config_revision: REVISION.to_string(),
            }
        );
        assert_eq!(
            new.route_weights.resolve("POST", "/v1/search")[0].evidence,
            Evidence::RouteWeight {
                config_revision: "0011223344ff".to_string(),
            }
        );
    }

    #[test]
    fn a_role_with_no_declared_resolvers_still_builds_an_empty_table() {
        // Recording the call without pricing it is a legitimate posture,
        // so this is not an error. The table is empty rather than absent
        // so the request path has one shape to handle.
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = metering_config(dir.path(), Vec::new(), Vec::new());

        let runtime = prepare_attestation(Some(&cfg), Some(&signer()), REVISION, NODE)
            .expect("builds")
            .expect("a declared role yields a runtime");

        assert!(runtime.measured.is_empty());
        assert!(runtime.route_weights.is_empty());
        assert!(runtime.origin_headers.is_empty());
        assert_eq!(runtime.route_weights.config_revision(), REVISION);
    }

    #[test]
    fn a_route_priced_and_reported_at_once_yields_one_unit_per_source() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = AttestationConfig {
            measured: vec![AttestationMeasuredConfig {
                name: "egress_kib".to_string(),
                quantity: AttestationMeasuredQuantity::BytesOut,
                per: 1024,
            }],
            ..metering_config(
                dir.path(),
                vec![AttestationRouteWeightConfig {
                    name: "search_call".to_string(),
                    method: None,
                    path: "/v1/search".to_string(),
                    weight: 1,
                }],
                vec![AttestationOriginHeaderConfig {
                    name: "result_row".to_string(),
                    header: "X-Rows-Returned".to_string(),
                }],
            )
        };
        let runtime = prepare_attestation(Some(&cfg), Some(&signer()), REVISION, NODE)
            .expect("builds")
            .expect("a declared role yields a runtime");

        let mut units = sbproxy_meter::resolve_measured(
            &runtime.measured,
            &sbproxy_meter::Measurement {
                bytes_in: 512,
                bytes_out: 12_043,
                duration_ms: 91,
            },
        );
        units.extend(runtime.route_weights.resolve("POST", "/v1/search"));
        units.extend(
            runtime
                .origin_headers
                .iter()
                .map(|rule| rule.resolve(Some("40")).unit),
        );

        let sources: Vec<UnitSource> = units.iter().map(|unit| unit.source).collect();
        assert_eq!(
            sources,
            vec![
                UnitSource::Measured,
                UnitSource::RouteWeight,
                UnitSource::OriginHeader
            ],
            "three provenances stay three lines; 53 would be one number nobody can check"
        );
    }

    #[test]
    fn a_measured_entry_lowers_with_the_divisor_that_makes_its_unit() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cfg = AttestationConfig {
            measured: vec![
                AttestationMeasuredConfig {
                    name: "egress_kib".to_string(),
                    quantity: AttestationMeasuredQuantity::BytesOut,
                    per: 1024,
                },
                AttestationMeasuredConfig {
                    name: "compute_second".to_string(),
                    quantity: AttestationMeasuredQuantity::DurationMs,
                    per: 1000,
                },
                AttestationMeasuredConfig {
                    name: "api_call".to_string(),
                    quantity: AttestationMeasuredQuantity::Requests,
                    per: 1,
                },
                AttestationMeasuredConfig {
                    name: "ingress_kib".to_string(),
                    quantity: AttestationMeasuredQuantity::BytesIn,
                    per: 1024,
                },
            ],
            ..metering_config(dir.path(), Vec::new(), Vec::new())
        };

        let runtime = prepare_attestation(Some(&cfg), Some(&signer()), REVISION, NODE)
            .expect("builds")
            .expect("a declared role yields a runtime");

        let units = sbproxy_meter::resolve_measured(
            &runtime.measured,
            &sbproxy_meter::Measurement {
                bytes_in: 2_048,
                bytes_out: 12_043,
                duration_ms: 1_500,
            },
        );
        let counts: Vec<(&str, u64)> = units
            .iter()
            .map(|unit| (unit.name.as_str(), unit.count))
            .collect();
        assert_eq!(
            counts,
            vec![
                ("egress_kib", 12),
                ("compute_second", 2),
                ("api_call", 1),
                ("ingress_kib", 2),
            ],
            "a partial unit is billed as a whole one"
        );
        assert!(units.iter().all(|unit| unit.source == UnitSource::Measured));
    }

    #[test]
    fn a_divisor_of_zero_falls_back_to_one_rather_than_panicking() {
        // `compile_config` rejects a zero divisor, so this is unreachable
        // through the supported path. It is a fallback anyway because this
        // is a runtime, and a runtime that panics on input it was told had
        // been validated takes the process down over somebody else's bug.
        let rule = measured_rule(&AttestationMeasuredConfig {
            name: "api_call".to_string(),
            quantity: AttestationMeasuredQuantity::Requests,
            per: 0,
        });

        assert_eq!(rule.per, NonZeroU64::MIN);
        assert_eq!(
            rule.resolve(&sbproxy_meter::Measurement::default()).count,
            1,
            "one unit per observed item is the reading an omitted key would have got"
        );
    }
}

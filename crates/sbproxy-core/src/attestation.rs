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
//! # Validation mode never touches the disk
//!
//! `prepare_attestation` creates the directories the queue and the
//! ledger live in, which is a real side effect and exactly the reason
//! the pipeline calls it only under
//! `PipelineConstructionMode::Runtime`. `sbproxy validate` must be able
//! to check a candidate config on an operator's laptop without leaving
//! ledger directories behind. Everything that can be decided without a
//! filesystem is decided earlier, at config compile, so validation still
//! rejects a broken block.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sbproxy_config::types::{
    AttestationBillableConfig, AttestationConfig, AttestationLedgerConfig, AttestationQueueConfig,
    AttestationRole, BillableRule, EnforcementMode, FailureMode, OriginAttestationConfig,
    WebBotAuthConfig, ATTESTATION_SIGN_WITH_WEB_BOT_AUTH,
};
use sbproxy_meter::{Billable, BillableOutcome, OutcomeTable};

/// The attestation posture one pipeline generation runs under.
///
/// Built once when a config is compiled and then immutable, so the
/// request path never re-reads YAML and a reload swaps the whole object
/// rather than mutating it underneath in-flight requests.
///
/// `Debug` is derived rather than hand-written because nothing here is
/// secret. `signing_key_id` is the `kid` that gets published in the
/// JWKS, and the rest is paths, counts, and postures. Should this ever
/// gain the seed itself rather than a name for it, replace the derive
/// with a manual impl that omits the key, the way the receipt and quote
/// signers do.
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
    /// Where unsettled claims are held.
    pub queue_path: PathBuf,
    /// How many unsettled claims to hold before
    /// [`Self::failure_mode`] applies.
    pub queue_max_entries: usize,
    /// Where settled records are chained.
    pub ledger_path: PathBuf,
    /// The operator's complete position on what they charge for.
    pub outcomes: OutcomeTable,
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
/// The queue and ledger directories are created here. That is the side
/// effect the caller gates on construction mode; see the module docs.
///
/// # Errors
///
/// Returns an error when a declared role has no queue, no ledger, or an
/// incomplete billing table, when `sign_with` names an identity this
/// build cannot resolve, or when a state directory cannot be created.
/// `compile_config` rejects the first three earlier, so reaching them
/// here means a pipeline was built from something other than a compiled
/// config; the checks stay because a runtime that assumes its input was
/// validated elsewhere is a runtime that panics when it was not.
pub(crate) fn prepare_attestation(
    cfg: Option<&AttestationConfig>,
    web_bot_auth: Option<&WebBotAuthConfig>,
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

    // Boot is the right time to find out the state directory is
    // unwritable. Discovering it at the first claim means the first
    // billable request of the deployment is also the first one that
    // takes the failure_mode branch.
    ensure_state_dir(&queue_path, "proxy.attestation.queue.path")?;
    ensure_state_dir(&ledger_path, "proxy.attestation.ledger.path")?;

    Ok(Some(Arc::new(AttestationRuntime {
        role,
        failure_mode,
        enforcement_mode,
        signing_key_id,
        queue_path,
        queue_max_entries,
        ledger_path,
        outcomes,
    })))
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
        assert!(prepare_attestation(None, None)
            .expect("absent block is not an error")
            .is_none());

        let off = AttestationConfig::default();
        assert_eq!(off.role, AttestationRole::Off);
        assert!(prepare_attestation(Some(&off), None)
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
        let proxy = AttestationConfig {
            role: AttestationRole::Both,
            ..AttestationConfig::default()
        };
        let origin = OriginAttestationConfig {
            role: Some(AttestationRole::Claim),
            agreement_id: Some("acme-2026".to_string()),
        };

        let resolved = resolve_origin_attestation(Some(&proxy), Some(&origin));

        assert_eq!(resolved.role, AttestationRole::Claim);
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
            role: AttestationRole::Both,
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

        let runtime = prepare_attestation(Some(&cfg), Some(&signer))
            .expect("a complete block builds")
            .expect("a declared role yields a runtime");

        assert_eq!(runtime.role, AttestationRole::Both);
        assert_eq!(runtime.signing_key_id.as_deref(), Some("sbproxy-2026"));
        assert_eq!(runtime.queue_max_entries, 4_096);
        assert_eq!(runtime.queue_path, queue_path);
        assert_eq!(runtime.ledger_path, ledger_path);
        assert_eq!(
            runtime.outcomes.billable(BillableOutcome::Retry),
            Billable::Collapse
        );
        assert!(
            queue_path
                .parent()
                .expect("the queue has a parent")
                .is_dir(),
            "boot creates the state directory so the first claim is not the first failure"
        );
    }

    #[test]
    fn a_receipt_role_without_its_named_signer_fails_loud() {
        let cfg = AttestationConfig {
            role: AttestationRole::Receipt,
            sign_with: Some(ATTESTATION_SIGN_WITH_WEB_BOT_AUTH.to_string()),
            queue: Some(AttestationQueueConfig {
                path: "claims.q".to_string(),
                max_entries: 16,
            }),
            ledger: Some(AttestationLedgerConfig {
                path: "receipts.ndjson".to_string(),
            }),
            billable: Some(complete_billable()),
            ..AttestationConfig::default()
        };

        let error = prepare_attestation(Some(&cfg), None)
            .expect_err("a receipt with nothing to sign it is not a receipt");
        assert!(
            error.to_string().contains("sign_with"),
            "the error names the key the operator has to fix: {error}"
        );
    }
}

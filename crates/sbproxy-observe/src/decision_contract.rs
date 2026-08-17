// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The published contract for decision-audit records (WOR-2448).
//!
//! What a consumer may rely on, per decision event: whether it publishes,
//! which structured fields its records carry, and where those fields sit
//! in the OCSF envelope.
//!
//! # Why this is a registry and not a docs page
//!
//! Retrofitting a field into a shipped record is a breaking change for
//! every SIEM rule selecting on it, so the field set is a promise rather
//! than an implementation detail. Prose cannot hold a promise: the
//! coverage statement in `observability.md` was wrong about `waf` for
//! months, because nothing compared it to the code.
//!
//! So the contract is declared here and checked against the code. The
//! declaration is hand-maintained on purpose, because a promise derived
//! from whatever the code currently does is not a promise. But every
//! claim in it is verified: [`FIELD_CONTRACTS`] names fields that must
//! exist on [`DecisionDetails`](crate::decision::DecisionDetails), and a
//! test fails when one does not.
//! `docs/decision-records.md` is generated from here, so the page and
//! the code cannot disagree.
//!
//! # Why every detail field is `unmapped`
//!
//! OCSF 1.6 defines `unmapped` as "a container for source-specific
//! attributes that do not map to any defined OCSF attribute", which is
//! exactly what these are. The class has no home for a model id, a tool
//! name, or an authentication method, and OCSF has no AI class and no
//! financial class to graduate them into.
//!
//! One field looked mappable and is not. API Activity defines `duration`,
//! but as "the elapsed time of the aggregation window in milliseconds
//! [...] only populate for aggregate events (`count` > 1)". Our
//! `decision_latency_ms` measures one decision, not a window, so putting
//! it there would publish a correct number under a wrong meaning. It
//! stays unmapped.
//!
//! This is settled rather than provisional: there is nothing to graduate
//! to. If OCSF adds an AI or control-decision class, moving a field is a
//! breaking change and gets its own deprecation window, the same way
//! `policy_record_format` handled the last one.

use crate::decision::{DecisionEvent, EventCoverage};

/// The structured fields one decision event's records carry.
pub struct FieldContract {
    /// The event these fields belong to.
    pub event: DecisionEvent,
    /// Field names, as they appear under `unmapped`.
    ///
    /// Every name here must exist on
    /// [`DecisionDetails`](crate::decision::DecisionDetails);
    /// `every_contracted_field_exists` proves it.
    pub fields: &'static [&'static str],
    /// What the consumer gets to rely on beyond the field names.
    pub note: &'static str,
}

/// Per-event field contracts, for the events that publish.
///
/// An event absent from this table publishes no structured detail, which
/// is a different claim from publishing no records: `cache.admit`
/// carries a reason and nothing else, and a rule against it has to
/// select on the reason or on the envelope.
pub const FIELD_CONTRACTS: &[FieldContract] = &[
    FieldContract {
        event: DecisionEvent::Policy,
        fields: &[
            "policy_id",
            "policy_surface",
            "verdict",
            "decision_latency_ms",
        ],
        note: "Only under `policy_record_format: decision`. `policy_id` is the module that \
               decided, which is how `waf` and the rate-limit family are selected now that \
               they have no separate event. `verdict` is the policy's own tag and is not the \
               record outcome: a faulted engine still returns a verdict while the decision \
               outcome is `error`.",
    },
    FieldContract {
        event: DecisionEvent::Auth,
        fields: &["auth_type"],
        note: "The method, never the subject. Details ship unredacted, and a resolved \
               principal is the one value on this path that is both attacker-influenced and \
               frequently personal; anything about who authenticated is in the scrubbed \
               reason. Published on allow and deny alike.",
    },
    FieldContract {
        event: DecisionEvent::RouteDecide,
        fields: &[
            "requested_model",
            "selected_model",
            "selected_provider",
            "tier_count",
            "dropped",
        ],
        note: "`requested_model` against `selected_model` is the field comparison behind \
               \"every decision that moved a request off the model it asked for\". `dropped` \
               non-zero means the plan that ran is not the plan the operator wrote.",
    },
    FieldContract {
        event: DecisionEvent::CacheKey,
        fields: &["skip_lookup", "vary_count"],
        note: "`vary_count` zero means the policy ran and added no dimensions, which is a \
               different fact from the policy not running.",
    },
    FieldContract {
        event: DecisionEvent::CacheAdmit,
        fields: &["stored", "ttl_secs", "swr_secs"],
        note: "An absent `ttl_secs` means the decision settled no TTL and the origin's \
               configured value applies. A zero would claim the decision chose none.",
    },
    FieldContract {
        event: DecisionEvent::AiGuardrailInput,
        fields: &["guardrail", "flagged_count"],
        note: "`guardrail` names the one that blocked and is absent on an allow, because no \
               single guardrail owns a decision they all passed. `flagged_count` carries the \
               near-miss signal on both, which is what makes an allow record worth storing.",
    },
    FieldContract {
        event: DecisionEvent::AiGuardrailOutput,
        fields: &["guardrail", "flagged_count"],
        note: "As the input event. Not published for a non-2xx response, because the \
               evaluator returns before inspecting one and a record there would claim an \
               allow no guardrail issued.",
    },
    FieldContract {
        event: DecisionEvent::AiToolCall,
        fields: &["tool", "verdict"],
        note: "One record per judged streamed tool call, not per chunk. `verdict` is the \
               guard's own word (`clean`, `blocked`, `flagged`), so a flag-mode judgement \
               that left the stream untouched is still countable.",
    },
    FieldContract {
        event: DecisionEvent::McpTool,
        fields: &["tool", "tool_server", "verdict"],
        note: "`verdict` is the dispatch label rather than the outcome, because only it \
               separates the gateway refusing a call (`policy_denied`, `tool_not_found`) \
               from the upstream failing one the gateway allowed (`tool_error`).",
    },
    FieldContract {
        event: DecisionEvent::AiFailure,
        fields: &["selected_provider", "verdict"],
        note: "`selected_provider` names which provider's response failed. `verdict` carries \
               the classified failure kind (`rate_limited`, `content_filter`, `upstream_5xx`, \
               `provider_error`), a closed vocabulary rather than the raw upstream status text, \
               which can carry a prompt fragment. The record's own `outcome` is always `error`: \
               this is an upstream fact, not a proxy policy decision.",
    },
    FieldContract {
        event: DecisionEvent::AiClose,
        fields: &["verdict"],
        note: "`verdict` carries the terminal `finish_reason` (`stop`, `length`, `tool_calls`, \
               `content_filter`, ...). Token counts and cost are not duplicated here: they \
               already have an authoritative home in the access log and the usage ledger, and \
               this record's job is marking that the stream reached its end, not re-billing it.",
    },
];

/// Envelope fields every record carries, whatever the event.
///
/// These are the OCSF-mapped half, and the part a consumer can write one
/// rule against across every decision the proxy makes. That single
/// cross-event shape is the whole point of the surface.
pub const ENVELOPE_FIELDS: &[(&str, &str)] = &[
    ("class_uid / class_name", "Always API Activity (6003)."),
    (
        "metadata.correlation_uid",
        "The request id. Joins every decision made on one request, and joins them to the \
         access log.",
    ),
    (
        "metadata.uid",
        "One UUID per record, for idempotent ingest.",
    ),
    (
        "cloud.org.name",
        "Tenant. Never empty; single-tenant deployments carry the default tenant.",
    ),
    (
        "api.service.name",
        "The origin's configured id, never the request Host. Under a wildcard origin the Host \
         is attacker-chosen.",
    ),
    ("api.operation", "The decision event's stable label."),
    ("policy.name", "The decision event's stable label."),
    ("policy.uid", "The rule id, when the engine exposes one."),
    (
        "policy.desc / message",
        "The reason, scrubbed. Prose for a human; do not write rules against it, because \
         rewording a script silently breaks a regex.",
    ),
    (
        "disposition_id / is_alert",
        "Security Control profile. `is_alert` is true for the outcomes that refused or \
         faulted.",
    ),
    ("actor.process.name", "The engine that decided."),
    (
        "unmapped",
        "Per-event structured detail, absent when the event has none. See the table above.",
    ),
];

/// Collapse the whitespace rustfmt's line continuations leave behind.
///
/// These notes wrap in the source for readability, and a wrapped string
/// carries the indentation with it. Inside a markdown table cell that
/// shows up as a run of spaces mid-sentence.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Render the published contract.
pub fn render_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Decision record contract\n");
    out.push_str("*Last modified: 2026-08-16*\n\n");
    out.push_str(
        "*Generated from the executable decision contract. Do not hand-edit; run \
         `cargo run -q -p sbproxy-observe --bin generate-decision-contract > \
         docs/decision-records.md`.*\n\n",
    );
    out.push_str(
        "What a consumer may rely on from the decision-audit feed. Retrofitting a field into \
         a shipped record breaks every rule selecting on it, so this page is a promise \
         rather than a description, and a drift guard proves the code still keeps it.\n\n",
    );

    out.push_str("## Coverage\n\n");
    out.push_str("| Event | Publishes | Notes |\n| --- | --- | --- |\n");
    for event in DecisionEvent::ALL {
        let (state, note) = match event.coverage() {
            EventCoverage::Emitted => ("yes", ""),
            EventCoverage::SupersededByPolicy => (
                "as `policy`",
                "Runs in the policy chain. Select on `unmapped.policy_id`; a separate emitter \
                 would put two records on the bus for one decision.",
            ),
            EventCoverage::DurableElsewhere => (
                "no, by design",
                "Recorded on the durable settlement store. This feed drops records under \
                 load, which is the wrong trade for money.",
            ),
            EventCoverage::ConfigDependent => (
                "with `policy_record_format: decision`",
                "Always reaches the audit bus. Under the default `legacy` format it arrives as                  `policy_verdict_event` on its own prefix instead of on this feed.",
            ),
            EventCoverage::NeverPublishes => (
                "never",
                "Fires once per streamed chunk, so it is refused ahead of both the per-event                  map and the master switch. `ai.close` carries the stream's summary once                  instead.",
            ),
            EventCoverage::Unwired => ("not yet", "No emitter. Enabling it publishes nothing."),
        };
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            event.as_label(),
            state,
            collapse(note)
        ));
    }

    out.push_str("\n## Structured detail\n\n");
    out.push_str(
        "Every field below rides under OCSF `unmapped`, which the spec defines as the \
         container for attributes a class does not define. The class has no home for a model \
         id, a tool name, or an authentication method, and OCSF has no AI class and no \
         financial class to graduate them into. `duration` is the one attribute that looks \
         mappable and is not: OCSF populates it only for aggregate events, so a per-decision \
         latency there would be a correct number under a wrong meaning.\n\n",
    );
    for contract in FIELD_CONTRACTS {
        out.push_str(&format!("### `{}`\n\n", contract.event.as_label()));
        for field in contract.fields {
            out.push_str(&format!("- `unmapped.{field}`\n"));
        }
        out.push_str(&format!("\n{}\n\n", collapse(contract.note)));
    }

    out.push_str("## Envelope\n\n");
    out.push_str("| Field | What it carries |\n| --- | --- |\n");
    for (field, meaning) in ENVELOPE_FIELDS {
        out.push_str(&format!("| `{field}` | {} |\n", collapse(meaning)));
    }

    out.push_str("\n## What may change without warning\n\n");
    out.push_str(
        "- The wording of any `reason`. It is prose for a human. Rules belong on fields.\n\
         - The addition of a new field under `unmapped`, which is additive and cannot break \
         a rule selecting on the fields already here.\n\
         - The addition of a new decision event.\n\n",
    );
    out.push_str("## What does not change without a deprecation window\n\n");
    out.push_str(
        "- Removing or renaming a field named on this page.\n\
         - Moving a field out of `unmapped` into a mapped OCSF attribute.\n\
         - Changing which event publishes a given decision.\n\
         - The stderr prefixes the bundled drain stamps.\n\n\
         The `policy_record_format` migration is the worked example of what that window \
         looks like: both shapes selectable, one record either way, the old one the default \
         for a release, and a startup warning naming the setting.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::DecisionDetails;

    /// Every field this page promises must exist on the type that ships
    /// it.
    ///
    /// The drift this catches is a rename: `DecisionDetails` is one flat
    /// struct shared by every family, so renaming a field compiles
    /// everywhere and silently breaks the promise for one event. Checked
    /// by serializing a fully-populated value and looking for the name
    /// on the wire, which is the same view a consumer has.
    #[test]
    fn every_contracted_field_exists_on_the_wire() {
        let populated = DecisionDetails {
            requested_model: Some("a".into()),
            selected_model: Some("a".into()),
            selected_provider: Some("a".into()),
            tier_count: Some(1),
            dropped: Some(0),
            stored: Some(true),
            ttl_secs: Some(1),
            swr_secs: Some(1),
            skip_lookup: Some(false),
            vary_count: Some(0),
            policy_id: Some("a".into()),
            policy_surface: Some("a".into()),
            verdict: Some("a".into()),
            decision_latency_ms: Some(1),
            auth_type: Some("a".into()),
            tool: Some("a".into()),
            tool_server: Some("a".into()),
            guardrail: Some("a".into()),
            flagged_count: Some(0),
        };
        let wire = serde_json::to_value(&populated).expect("serializes");
        let object = wire.as_object().expect("detail is an object");
        for contract in FIELD_CONTRACTS {
            for field in contract.fields {
                assert!(
                    object.contains_key(*field),
                    "`{}` promises `unmapped.{field}`, which no longer exists on \
                     DecisionDetails. Renaming a field there compiles everywhere and breaks \
                     this promise silently, so either restore the name or take it through a \
                     deprecation window",
                    contract.event.as_label()
                );
            }
        }
    }

    /// A contract may only be declared for an event that publishes.
    ///
    /// Promising fields on a feed nobody receives is the same failure as
    /// the coverage statement that claimed `waf` was unwired: a
    /// statement about the system that the system does not honor.
    #[test]
    fn only_publishing_events_declare_fields() {
        for contract in FIELD_CONTRACTS {
            let coverage = contract.event.coverage();
            assert!(
                matches!(
                    coverage,
                    EventCoverage::Emitted | EventCoverage::ConfigDependent
                ),
                "`{}` declares a field contract but its coverage is {coverage:?}",
                contract.event.as_label()
            );
        }
    }

    /// Every publishing event has to say what it carries.
    ///
    /// Catches the direction the other tests cannot: wiring an emitter
    /// and forgetting to publish its contract, which leaves a consumer
    /// reading fields nobody promised and we are free to remove.
    #[test]
    fn every_publishing_event_declares_its_detail() {
        // `cache.admit` and the rest all carry detail today. An event
        // that genuinely carries none belongs on this list with a
        // sentence saying so, not silently absent.
        const CARRIES_NO_DETAIL: &[DecisionEvent] = &[];
        for event in DecisionEvent::ALL {
            if !matches!(event.coverage(), EventCoverage::Emitted) {
                continue;
            }
            let declared = FIELD_CONTRACTS.iter().any(|c| c.event == *event);
            assert!(
                declared || CARRIES_NO_DETAIL.contains(event),
                "`{}` publishes but declares no field contract; add one to FIELD_CONTRACTS so \
                 a consumer knows what it may rely on",
                event.as_label()
            );
        }
    }

    #[test]
    fn the_rendered_page_names_every_event() {
        let page = render_markdown();
        for event in DecisionEvent::ALL {
            assert!(
                page.contains(event.as_label()),
                "the generated page omits `{}`",
                event.as_label()
            );
        }
    }
}

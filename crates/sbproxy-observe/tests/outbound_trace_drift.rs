// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The outbound trace-propagation guard.
//!
//! `metric_drift.rs` covers the metrics vocabulary and `span_drift.rs`
//! covers the span one. Neither covers the thing a trace is actually made
//! of, which is the `traceparent` header on the way out.
//!
//! What was live on `main` when this landed: the proxied upstream request
//! carried a W3C `traceparent` and every other HTTP call the proxy makes
//! on a customer's behalf did not. `docs/observability.md` said so, named
//! four of those clients, and admitted "there is no CI gate enforcing it
//! yet". That admission is the failure mode this file exists to remove.
//! An unenforced propagation contract does not decay loudly: the trace
//! simply stops at the proxy, and the operator reading it has no way to
//! tell a call that was never made from one that was made untraced.
//!
//! W3C Trace Context: <https://www.w3.org/TR/trace-context/>.
//!
//! # What is checked, and what is not
//!
//! The unit is the **file**, not the call site. Every production file
//! under `crates/` that builds an outbound HTTP client, or sends through
//! one, must appear in exactly one of [`INJECTS`] or [`EXEMPT`]. A new
//! outbound client in a file that is in neither fails the build and names
//! the file.
//!
//! Two limitations, stated rather than left to be discovered:
//!
//! 1. A file with several outbound calls passes on one injection. The
//!    guard proves the injector is reachable in that file, not that every
//!    request builder in it goes through the injector. Narrowing the unit
//!    to the call site means resolving which receiver is a `reqwest`
//!    builder through aliases, helper functions, and closures, which is a
//!    type-checker's job rather than a scanner's.
//! 2. A file that receives an already-built `reqwest::Client` and sends
//!    through it is caught by the send markers, not the construction
//!    markers, and the send markers are textual. A send spelled in a way
//!    [`SEND_MARKERS`] does not list is invisible.
//!    `the_scanner_sees_the_outbound_files_it_thinks_it_does` pins the
//!    floor so a scanner that quietly stopped reading cannot pass.
//!
//! # The exemption table is the point
//!
//! Forty-two files are exempt today, and that is not a failure state: a
//! release-artifact download at boot, a CLI subcommand, and a background
//! poll timer have no request whose trace they could join. What matters is
//! that each one says so in a line a reviewer reads, rather than being
//! silently absent. Where a site is uninjected because the plumbing has
//! not been done yet, the reason says that too, in those words.
//!
//! Every reason names WOR-2318, the ticket that either wires the site or
//! deletes the row. There is no second ticket to point at, and an
//! admission with no tracker is the state this guard replaces.

use sbproxy_capability::scan;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sbproxy-observe -> crates -> repo root")
        .to_path_buf()
}

/// Expressions that build an outbound HTTP client.
///
/// A file that names one of these owns a client, whether or not it also
/// sends through it, so it is part of the outbound surface even when the
/// send lives one module away.
const CLIENT_MARKERS: &[&str] = &[
    "reqwest::Client::new",
    "reqwest::Client::builder",
    "reqwest::blocking::Client::new",
    "reqwest::blocking::Client::builder",
    "reqwest::get(",
    "reqwest::blocking::get(",
    "OutboundClientBuilder::new",
    "default_outbound()",
    "token_bearing_outbound()",
    "ureq::get(",
    "ureq::post(",
    "ureq::put(",
    "ureq::delete(",
    "ureq::request(",
];

/// Expressions that send an outbound HTTP request.
///
/// Only consulted in a file that already mentions `reqwest` or `ureq`,
/// because `.send()` and `.execute(` are far too common otherwise: the
/// SQLite stores, the Redis client, and all four scripting engines call
/// `.execute(` on things that never touch a socket. `.execute(request`
/// rather than `.execute(` for the same reason, narrowed to the one
/// spelling every real `reqwest::Client::execute` call site in this
/// workspace uses.
const SEND_MARKERS: &[&str] = &[
    ".send()",
    ".send_json(",
    ".send_form(",
    ".execute(request",
    ".execute(req)",
];

/// Calls that attach trace context to an outbound request.
///
/// `outbound_trace_headers` and `inject_reqwest_trace_context` are the
/// pair added for this work; the other three predate it and are still
/// correct answers, which is why the MCP gateway's OpenAPI dispatch
/// counts as injecting without being rewritten.
const INJECTOR_MARKERS: &[&str] = &[
    "inject_reqwest_trace_context",
    "outbound_trace_headers",
    "inject_into_reqwest",
    "inject_into_headers",
    "propagation_pairs",
];

/// Files that make an outbound HTTP call and attach the trace context.
const INJECTS: &[&str] = &[
    // The forward-auth subrequest, inside `sbproxy.intake.authenticate`.
    "crates/sbproxy-core/src/server.rs",
    // Webhook delivery and the request mirror, both carrying the context
    // explicitly because both dispatch through a spawned task.
    "crates/sbproxy-core/src/server/callbacks.rs",
    // The OIDC callback's token exchange and userinfo fetch.
    "crates/sbproxy-core/src/server/request_phase.rs",
    // MCP: `_meta` on the JSON-RPC body for the stdio-capable transports,
    // headers on the OpenAPI-backed REST dispatch.
    "crates/sbproxy-extension/src/mcp/federation.rs",
    // The Web Bot Auth signature-agent directory fetch.
    "crates/sbproxy-modules/src/auth/bot_auth_directory.rs",
    // Vault Transit wrap and unwrap for the customer-managed root of trust.
    // Unlike the read backends in this crate, these sit on the credential
    // resolution path, so there is a request behind them; the caller
    // captures the pairs on the async side because `spawn_blocking` loses
    // the ambient context. WOR-2568.
    "crates/sbproxy-vault/src/transit.rs",
    // The `ext_authz` authorization callout (WOR-2667).
    "crates/sbproxy-modules/src/auth/ext_authz.rs",
    // The KYA issuer's JWKS and denylist fetches (WOR-2667).
    "crates/sbproxy-modules/src/auth/kya.rs",
    // The RFC 7662 introspection call (WOR-2667).
    "crates/sbproxy-modules/src/auth/oauth_introspection.rs",
    // The OAuth token exchange and client-credentials grant.
    "crates/sbproxy-modules/src/auth/outbound_credential.rs",
    // The AI-crawl ledger redeem call.
    "crates/sbproxy-modules/src/policy/ai_crawl/http_ledger.rs",
];

/// A reviewed, ticketed exception to the propagation rule.
///
/// Same shape and same bargain as `scan::ReferenceExemption`, which the
/// metric guard uses: a line in a table a reviewer reads, against a
/// silently untraced hop.
#[derive(Debug, Clone, Copy)]
struct Exemption {
    /// Path relative to the repo root.
    file: &'static str,
    /// Why the call leaves without a `traceparent`, and the ticket that
    /// changes that.
    reason: &'static str,
}

/// Every outbound-HTTP file that does not inject, and why.
///
/// Three kinds of entry, and the reason says which:
///
/// - **No trace to join.** Boot, config compile, CLI, and background
///   timers. There is no request whose trace these belong to, and
///   inventing a root per call would fill a backend with orphan
///   single-span traces that look real. These stay exempt.
/// - **The span is lost at a spawn boundary.** The work is scheduled by
///   something that had a trace, but the task does not inherit
///   `tracing::Span::current()` and nothing hands the context over.
///   Fixable, by propagating explicitly from the scheduler the way the
///   webhook and mirror paths now do.
/// - **On the request path, not yet plumbed.** The context exists and is
///   reachable; the wiring is the work.
const EXEMPT: &[Exemption] = &[
    Exemption {
        file: "crates/sbproxy-ai/src/client.rs",
        reason: "On the request path and not yet plumbed. The AI provider call is the \
                 largest remaining gap: it sends a prebuilt `reqwest::Request` through a \
                 governed redirect loop, so injection has to happen on the header map \
                 rather than a builder, and it has to survive each hop. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-ai/src/external_guardrail/mod.rs",
        reason: "On the AI request path and not yet plumbed. The guardrail provider call \
                 runs inside AI dispatch, so the ambient span is available and this is a \
                 one-line change once the AI slice is taken as a whole. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-ai/src/health_probe.rs",
        reason: "Background timer with no scheduling request. A provider health probe \
                 runs on an interval and belongs to no caller's trace, so there is \
                 nothing to propagate rather than something missing. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-ai/src/judge/client.rs",
        reason: "Driven by the classifier sidecar's gRPC service, not by an HTTP request \
                 through this proxy. Trace context for that entry point arrives as gRPC \
                 metadata and has no extraction path here yet. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-ai/src/judge/compat_judge.rs",
        reason: "On the MCP tool-dispatch path and not yet plumbed. Reachable from the \
                 same dispatch that already injects on its OpenAPI arm, so this is a \
                 gap in coverage rather than in mechanism. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-ai/src/prompt_optimizer.rs",
        reason: "CLI only. Its single in-tree constructor is a `sbproxy` subcommand, so \
                 there is no request and no trace for the optimization call to join. \
                 WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-ai/src/semantic_cache.rs",
        reason: "On the AI request path and not yet plumbed. The embedding call for a \
                 semantic-cache probe happens inside dispatch, where the ambient span is \
                 live. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-ai/src/toolkit/runtime.rs",
        reason: "Constructor only, and the send site it feeds already injects. This file \
                 builds the toolkit's no-redirect agent client and never sends through \
                 it; every governed agent hop is built and dispatched in \
                 `crates/sbproxy-ai/src/toolkit/workflow.rs`, which attaches the context \
                 with `inject_reqwest_trace_context`. The scan classifies on the client \
                 constructor, so the owning file needs a row even when nothing leaves \
                 untraced. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-ai/src/usage_sink.rs",
        reason: "The span is lost at a spawn boundary. Usage records post from a \
                 `tokio::spawn` so the hot path is not blocked, and the spawn is not \
                 instrumented, so the ambient context is gone by the time the request is \
                 built. Needs the context moved into the task. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-billing/src/transport/http.rs",
        reason: "The shared settlement transport. Its reconciliation caller already opens \
                 `sbproxy.rail.reconcile`, so a span exists and only the injection is \
                 missing, but the settlement union is a separate compile lane and this \
                 change did not build it. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-classifiers/src/lib.rs",
        reason: "Boot-time artifact download. ONNX weights, tokenizer, and detached \
                 signature are fetched while the classifier loads, before any request \
                 exists. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-core/src/admin_playground.rs",
        reason: "Admin API surface, not the data path. Both calls are made while serving \
                 an operator's admin request; the admin server does not open a pillar \
                 span, so there is no context to read yet. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-core/src/config_soak.rs",
        reason: "Background timer with no scheduling request. The config soak's operator \
                 probe fires on its own interval to judge a config revision that has \
                 already applied, so it belongs to no caller's trace and there is nothing \
                 to propagate rather than something missing. The same reasoning as the AI \
                 provider health probe beside it. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-core/src/config_subscriber.rs",
        reason: "Background poll on a dedicated thread with its own runtime. The config \
                 authority is polled on a timer with no scheduling request, so there is \
                 no trace to join. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-core/src/dispatch.rs",
        reason: "The HTTP/3 dispatcher, which is the reqwest twin of the Pingora proxy \
                 path and does not inject where its twin does. No H3 listener is wired \
                 today, so nothing reaches it, which is exactly why it drifted. \
                 WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-core/src/model_plane/server.rs",
        reason: "The mesh worker forwarding an inbound model-plane request to its local \
                 engine. Request-scoped, but the inbound side is the mesh transport \
                 rather than the proxy pipeline, so no `RequestContext` and no pillar \
                 span exist on it. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-core/src/server/action_dispatch.rs",
        reason: "Builds a client the action dispatcher hands elsewhere and sends nothing \
                 itself. Listed so the construction is visible; the row goes away when \
                 the consumer is covered. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-core/src/server/model_host.rs",
        reason: "On the AI request path and not yet plumbed. The loopback call to a \
                 locally hosted engine runs under AI dispatch. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-security/src/governed_egress.rs",
        reason: "The governed dial itself, which owns the per-hop pinned client every \
                 caller now sends through (WOR-2612, WOR-2620). It takes a prebuilt \
                 `reqwest::Request` and knows nothing about the span that produced it, \
                 so the context has to be injected by the caller before it arrives \
                 here. Its two callers are the MCP run-as-user token exchange, which \
                 is on the request path and not yet plumbed, and the events webhook, \
                 which is a background batch with no single request to join. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-extension/src/mcp/sse_client.rs",
        reason: "MCP carries trace context in the JSON-RPC body's `params._meta`, which \
                 `federation.rs` fills before calling this, because `_meta` is the one \
                 carrier that also works on the stdio transport. The HTTP header is \
                 additionally worth setting for the hops that have one. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-extension/src/mcp/streamable.rs",
        reason: "Same as the SSE transport: the context rides `params._meta` in the body \
                 that `federation.rs` builds, and the HTTP header is not also set. \
                 WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-httpkit/src/outbound.rs",
        reason: "The shared bounded-client builder, and structurally the wrong layer for \
                 this. `reqwest` fixes `default_headers` when the client is built, so a \
                 client-level default cannot carry a per-request `traceparent`; \
                 injection belongs on the request builder. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-k8s-operator/src/main.rs",
        reason: "A separate operator binary. Its reconcile loop posts a reload to each \
                 proxy pod on a Kubernetes watch event, which is not a request through \
                 any proxy. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-model-host/src/artifact/http.rs",
        reason: "Model-weight download at boot or on an operator's `models pull`. Gigabyte \
                 artifact transfers with no request behind them. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-model-host/src/cuda_build.rs",
        reason: "Provisioning. Fetches a llama.cpp source tarball to build a CUDA engine, \
                 before the proxy serves anything. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-model-host/src/llama_release.rs",
        reason: "Provisioning. Downloads a `llama-server` release asset during engine \
                 setup, with no request in scope. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-model-host/src/mistralrs_release.rs",
        reason: "Provisioning. Downloads a mistral.rs release asset during engine setup, \
                 with no request in scope. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-model-host/src/uv_release.rs",
        reason: "Provisioning. Downloads the `uv` release the Python engines need, with \
                 no request in scope. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-modules/src/action/loadbalancer.rs",
        reason: "Background timer. Active health probes run on an interval against each \
                 target and belong to no caller's trace. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-modules/src/action/mcp.rs",
        reason: "Builds the judge transport's client and sends nothing itself. The send \
                 is in `sbproxy-ai`'s judge client, which has its own row. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-modules/src/action/mod.rs",
        reason: "Config compile time. A remote bulk-redirect list is fetched while the \
                 action is built, which happens at boot and on reload, not per request. \
                 WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-modules/src/auth/jwks.rs",
        reason: "Two contexts, one file. The unknown-kid refetch is on the request path \
                 and could inject from the ambient auth span; the periodic refresh runs \
                 in an uninstrumented `tokio::spawn` and has no context to read. \
                 WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-modules/src/auth/mod.rs",
        reason: "Builds an auth provider's client and sends nothing itself. Listed so the \
                 construction stays visible. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-modules/src/policy/ai_crawl/mod.rs",
        reason: "Builds the blocking client the ledger uses and sends nothing itself. The \
                 send is in `http_ledger.rs`, which injects. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-modules/src/policy/waf/feed.rs",
        reason: "Background poll. The WAF rule feed is refetched on a loop with a \
                 conditional GET; no request scheduled it. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-modules/src/projections/agent_skills.rs",
        reason: "Projection build time. A remote agent-skill artifact is fetched while \
                 the index is rendered from config, not per request. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-observe/src/event_ingest/mod.rs",
        reason: "The span is lost at a spawn boundary, and a batch has no single trace \
                 to join. The ingest worker owns its own runtime and drains a queue, so \
                 nothing is current when it publishes, and one NATS flush or one \
                 ClickHouse insert carries events from many unrelated requests. A \
                 traceparent there would name whichever request happened to be first in \
                 the batch, which is worse than none: it renders as a real edge. The \
                 event's own `request_id` is already a field of the payload, which is \
                 where a warehouse join belongs. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-observe/src/notify/mod.rs",
        reason: "The span is lost at a spawn boundary. The notifier's delivery worker \
                 owns its own runtime and drains a queue, so nothing is current when it \
                 sends, and the last of three attempts lands about five seconds after \
                 the request that produced the event has finished, or far later still \
                 when an operator replays it out of the deadletter queue. The delivery \
                 carries the event's own id in a header instead, which is the \
                 correlation a receiver can actually act on. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-observe/src/event_sink.rs",
        reason: "The span is lost at a spawn boundary, and a batch has no single \
                 trace to join. The webhook worker owns its own runtime and drains a \
                 queue, so nothing is current when it sends, and one POST carries \
                 events from many unrelated requests. A traceparent there would name \
                 whichever request happened to be first in the batch, which is worse \
                 than none: it renders as a real edge. Per-event context would have to \
                 ride in the payload rather than the header. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-observe/src/alerting/channels.rs",
        reason: "The span is lost at a spawn boundary. Alert webhooks are dispatched \
                 through an uninstrumented task set, and an alert is usually raised by a \
                 rule evaluation rather than by one request, so what the propagated \
                 context should be is a design question rather than a wiring gap. \
                 WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-rag/src/http.rs",
        reason: "On the AI request path and not yet plumbed. This is the single send for \
                 every RAG embedding and vector provider, so one injection here covers \
                 six backends. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-tls/src/acme.rs",
        reason: "Background certificate renewal on the maintenance handle. Directory, \
                 nonce, and every signed ACME POST run on a timer with no request behind \
                 them. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-tls/src/ocsp.rs",
        reason: "Background OCSP stapling refresh on the maintenance handle, on a timer \
                 with no request behind it. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-vault/src/azure.rs",
        reason: "Secret resolution over `ureq`, through the synchronous `VaultBackend` \
                 trait. Runs at boot and on token refresh, and the trait has no place to \
                 carry a request context even where a caller has one. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-vault/src/gcp.rs",
        reason: "Secret resolution over `ureq`, through the synchronous `VaultBackend` \
                 trait, including the workload-identity token exchange. Same trait \
                 constraint as the Azure backend. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-vault/src/hashicorp.rs",
        reason: "Secret resolution over `ureq`, through the synchronous `VaultBackend` \
                 trait, including AppRole and Kubernetes login. Same trait constraint as \
                 the Azure backend. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy/src/main.rs",
        reason: "The CLI binary. Self-update, cluster enrollment, `apply`, and the admin \
                 subcommands all run in a one-shot process with no request and no tracer \
                 installed. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-federation/src/http_fetcher.rs",
        reason: "The OpenID Federation trust-chain walk. Nothing in the OSS request path \
                 composes a chain today: `proxy.federation` serves this entity's own \
                 statement and does not fetch anyone else's, so there is no request whose \
                 trace these GETs could join. The row moves to INJECTS the day a live \
                 authentication consumer drives the resolver. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-mcp-gateway/src/as_metadata.rs",
        reason: "The broker's upstream authorization-server metadata and JWKS fetches. \
                 Cached and refreshed behind whichever OAuth request happened to miss the \
                 cache, so the call belongs to no one caller's trace even when a request \
                 triggered it. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-mcp-gateway/src/cimd.rs",
        reason: "Client Instance Metadata Document retrieval, on the OAuth request path \
                 and not yet plumbed. Same standalone-router constraint as the \
                 `/authorize` leg. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-mcp-gateway/src/cimd_to_dcr.rs",
        reason: "Dynamic client registration derived from a CIMD, on the OAuth request \
                 path and not yet plumbed. Same standalone-router constraint as the \
                 `/authorize` leg. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-mcp-gateway/src/egress.rs",
        reason: "Builds the broker's outbound client and sends nothing itself. The sends \
                 are in the endpoint modules, each of which carries its own row here. \
                 Listed so the construction stays visible. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-mcp-gateway/src/introspect.rs",
        reason: "RFC 7662 token introspection against the upstream authorization server, \
                 on the OAuth request path and not yet plumbed. Same standalone-router \
                 constraint as the `/authorize` leg. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-mcp-gateway/src/lib.rs",
        reason: "Builds the broker runtime's shared client and sends nothing itself. The \
                 sends are in the endpoint modules; since every one of them now takes its \
                 client from `egress.rs` rather than building its own, only `egress.rs` \
                 and this file carry a client marker, so the scanner no longer sees \
                 `authorize.rs`, `token.rs`, or `resource_server.rs`. Their sends are \
                 still on the OAuth request path and still unplumbed, for the same \
                 standalone-router reason. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-mcp-gateway/src/revoke.rs",
        reason: "RFC 7009 revocation forwarded to the upstream authorization server, on \
                 the OAuth request path and not yet plumbed. Same standalone-router \
                 constraint as the `/authorize` leg. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-mcp-gateway/src/token_exchange.rs",
        reason: "RFC 8693 exchange against the upstream authorization server, on the \
                 OAuth request path and not yet plumbed. Same standalone-router \
                 constraint as the `/authorize` leg. WOR-2318.",
    },
    Exemption {
        file: "crates/sbproxy-extension/src/bundle/outbound.rs",
        reason: "A bundle hook's granted `net:outbound` call, built from a guest-supplied \
                 request on a blocking pool thread detached from the request's ambient \
                 span. Whether a guest-initiated fetch should carry the end user's trace \
                 into a third-party destination is a deliberate propagation question, not \
                 a plumbing oversight. WOR-2318.",
    },
];

/// One production file that owns or drives an outbound HTTP client.
#[derive(Debug, Clone)]
struct OutboundFile {
    /// Path relative to the repo root, with forward slashes.
    path: String,
    /// Whether any injector call appears in the file's production text.
    injects: bool,
    /// The markers that put it in this set, for a failure message that
    /// says what was found rather than only that something was.
    markers: Vec<&'static str>,
}

/// Every production file under `crates/` that builds or drives an
/// outbound HTTP client.
///
/// `scan::rust_sources` supplies the corpus: `crates/*/src` reachable
/// from each crate root, with `#[cfg(test)]` items and `#[test]`
/// functions already stripped, and with integration tests, benches,
/// examples, conventional `tests.rs` modules, and `e2e/` excluded. A
/// client built only to drive a test is therefore not part of this
/// surface, which is the right answer: it never leaves the machine.
fn outbound_files(root: &Path) -> Vec<OutboundFile> {
    let mut out = Vec::new();
    for source in scan::rust_sources(root) {
        let path = source.path.to_string_lossy().replace('\\', "/");
        if path.ends_with("/tests.rs") || path.ends_with("/test_support.rs") {
            continue;
        }
        let text = source.text.as_str();
        let mut markers: Vec<&'static str> = Vec::new();
        for marker in CLIENT_MARKERS {
            if text.contains(*marker) {
                markers.push(*marker);
            }
        }
        if text.contains("reqwest") || text.contains("ureq::") {
            for marker in SEND_MARKERS {
                if text.contains(*marker) {
                    markers.push(*marker);
                }
            }
        }
        if markers.is_empty() {
            continue;
        }
        let injects = INJECTOR_MARKERS.iter().any(|marker| text.contains(*marker));
        out.push(OutboundFile {
            path,
            injects,
            markers,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Classify `files` against `injects` and `exempt`, returning one message
/// per violation.
///
/// Taken as parameters rather than read from the constants so the last
/// two tests can plant fixtures and prove the guard fires. A guard whose
/// tables are baked in can only be shown to pass.
fn classification_errors(
    files: &[OutboundFile],
    injects: &[&str],
    exempt: &[Exemption],
) -> Vec<String> {
    let injects: BTreeSet<&str> = injects.iter().copied().collect();
    let exempt_paths: BTreeSet<&str> = exempt.iter().map(|entry| entry.file).collect();
    let mut errors = Vec::new();

    for file in files {
        let path = file.path.as_str();
        let listed_injecting = injects.contains(path);
        let listed_exempt = exempt_paths.contains(path);

        if !listed_injecting && !listed_exempt {
            errors.push(format!(
                "{path} makes an outbound HTTP call ({}) and is in neither table. Attach \
                 the request's trace context with \
                 `sbproxy_observe::telemetry::inject_reqwest_trace_context` (or \
                 `outbound_trace_headers` for a carrier that is not a reqwest builder) \
                 and add it to INJECTS, or add an EXEMPT row saying why this call has no \
                 trace to join",
                file.markers.join(", ")
            ));
            continue;
        }
        if listed_injecting && listed_exempt {
            errors.push(format!(
                "{path} is in both INJECTS and EXEMPT; it has to be one or the other"
            ));
            continue;
        }
        if listed_injecting && !file.injects {
            errors.push(format!(
                "{path} is listed as injecting and names no injector. Either the \
                 injection was removed and the outbound call is now untraced, or the \
                 call moved and the row is stale"
            ));
        }
        if listed_exempt && file.injects {
            errors.push(format!(
                "{path} is listed as exempt and now injects. Move it to INJECTS; an \
                 exemption that has been fixed rots into the stale admission this guard \
                 replaced"
            ));
        }
    }

    let found: BTreeSet<&str> = files.iter().map(|file| file.path.as_str()).collect();
    for path in injects.iter().chain(exempt_paths.iter()) {
        if !found.contains(path) {
            errors.push(format!(
                "{path} is listed but is no longer a production outbound-HTTP file. \
                 Delete the row; a table nobody prunes stops describing the code"
            ));
        }
    }

    errors
}

fn report(what: &str, errors: &[String]) {
    assert!(
        errors.is_empty(),
        "{what}\n\n{}\n",
        errors
            .iter()
            .map(|error| format!("  - {error}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_outbound_http_file_is_classified() {
    let files = outbound_files(&repo_root());
    report(
        "An outbound HTTP call is unaccounted for. Every helper call the proxy makes on \
         a customer's behalf either carries the request's W3C trace context or says in \
         one reviewed line why it has none.",
        &classification_errors(&files, INJECTS, EXEMPT),
    );
}

#[test]
fn the_scanner_sees_the_outbound_files_it_thinks_it_does() {
    // `classification_errors` is satisfied by an empty file list, so a
    // scanner that read nothing, or a `rust_sources` that returned an
    // empty corpus, would pass the test above. Pin the floor, and pin it
    // against files chosen so a plausible regression breaks one of them:
    // one async client, one blocking client, one `ureq` backend, one that
    // only builds a client, and one that only sends through a client it
    // was handed.
    let files = outbound_files(&repo_root());
    let found: BTreeSet<&str> = files.iter().map(|file| file.path.as_str()).collect();

    assert!(
        found.len() >= 40,
        "the scanner found only {} outbound files under crates/; it is not reading what \
         it thinks it is: {found:?}",
        found.len()
    );

    for expected in [
        // async reqwest, constructed and sent in the same file
        "crates/sbproxy-core/src/server/callbacks.rs",
        // blocking reqwest
        "crates/sbproxy-modules/src/policy/ai_crawl/http_ledger.rs",
        // ureq, no reqwest anywhere in the file
        "crates/sbproxy-vault/src/hashicorp.rs",
        // builds a client, sends nothing
        "crates/sbproxy-httpkit/src/outbound.rs",
        // sends through a client it was handed, constructs none
        "crates/sbproxy-modules/src/auth/outbound_credential.rs",
    ] {
        assert!(
            found.contains(expected),
            "{expected} plainly makes or drives an outbound HTTP call and the scanner \
             missed it: {found:?}"
        );
    }
}

#[test]
fn an_exempt_outbound_call_names_a_reason_and_a_ticket() {
    // The same rule the metric and span registries carry. An admission
    // with no reason is indistinguishable from an oversight, and one with
    // no tracker decays back into "nobody noticed".
    for exemption in EXEMPT {
        let Exemption { file, reason } = exemption;
        assert!(
            reason.len() > 60,
            "{file} needs a real reason, not '{reason}'"
        );
        assert!(
            reason.contains("WOR-"),
            "{file} must name the ticket that wires or deletes it: '{reason}'"
        );
    }
}

#[test]
fn no_outbound_file_is_listed_twice() {
    let mut listed: Vec<&str> = INJECTS
        .iter()
        .copied()
        .chain(EXEMPT.iter().map(|entry| entry.file))
        .collect();
    listed.sort_unstable();
    let before = listed.len();
    listed.dedup();
    assert_eq!(
        before,
        listed.len(),
        "a file appears twice across INJECTS and EXEMPT"
    );
}

#[test]
fn the_guard_catches_an_unclassified_outbound_call() {
    // A guard with no proof it can fail is not a guard. The tables pass
    // today, so `every_outbound_http_file_is_classified` is satisfied by
    // an empty corpus, a broken scanner, or a real absence of violations,
    // and it cannot tell you which. Empty tables pin it to the third.
    let files = outbound_files(&repo_root());
    let errors = classification_errors(&files, &[], &[]);

    assert!(
        errors.len() >= 40,
        "with both tables empty every outbound file should be reported, got {}: {errors:?}",
        errors.len()
    );
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("crates/sbproxy-core/src/server/callbacks.rs")),
        "the webhook path is plainly an outbound file and was not reported: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .all(|error| error.contains("inject_reqwest_trace_context") || error.contains("EXEMPT")),
        "every failure has to say what to do about it: {errors:?}"
    );
}

#[test]
fn the_guard_catches_an_injection_that_was_removed() {
    // The other direction, and the one that matters most over time: a
    // file the table calls injecting whose injector call was deleted. The
    // outbound call still compiles, its tests still pass, and the trace
    // silently stops there.
    //
    // The fixture is a real file that really does not inject, so the
    // guard is being shown to distinguish "no injector" from "no file".
    // A made-up path would fail through the stale-row branch instead and
    // prove nothing about the check under test.
    let files = outbound_files(&repo_root());
    let planted = "crates/sbproxy-tls/src/acme.rs";

    let errors = classification_errors(
        &files,
        &[planted],
        &EXEMPT
            .iter()
            .copied()
            .filter(|entry| entry.file != planted)
            .collect::<Vec<_>>(),
    );

    let hit = errors
        .iter()
        .find(|error| error.starts_with(planted))
        .unwrap_or_else(|| panic!("the guard did not fire for {planted}: {errors:?}"));
    assert!(
        hit.contains("names no injector"),
        "the failure has to name the reason, not just fail: {hit}"
    );
}

#[test]
fn the_guard_catches_an_exemption_that_was_fixed() {
    // And the flattering direction. A row that says "no trace to join"
    // over a call that now injects is a lie in the table, and the table
    // is the only thing a reviewer reads.
    let files = outbound_files(&repo_root());
    let planted = "crates/sbproxy-modules/src/auth/bot_auth_directory.rs";

    let mut exempt: Vec<Exemption> = EXEMPT.to_vec();
    exempt.push(Exemption {
        file: planted,
        reason: "A fixture that must never exist in EXEMPT (WOR-2318).",
    });
    let injects: Vec<&str> = INJECTS
        .iter()
        .copied()
        .filter(|path| *path != planted)
        .collect();

    let errors = classification_errors(&files, &injects, &exempt);

    let hit = errors
        .iter()
        .find(|error| error.starts_with(planted))
        .unwrap_or_else(|| panic!("the reverse guard did not fire: {errors:?}"));
    assert!(
        hit.contains("now injects"),
        "the failure has to say the call went live: {hit}"
    );
}

#[test]
fn the_documented_propagation_contract_matches_the_tables() {
    // The doc is what an operator reads before deciding whether a gap in
    // their trace is their misconfiguration or ours. It used to say the
    // helper clients "do not inject `traceparent` today, and there is no
    // CI gate enforcing it yet", which was true and is the sentence this
    // whole file exists to retire. Pin the replacement to the tables so
    // the counts in it cannot drift.
    let path = repo_root().join("docs/observability.md");
    let doc = std::fs::read_to_string(&path).expect("read docs/observability.md");

    assert!(
        !doc.contains("there is no CI gate enforcing it yet"),
        "docs/observability.md still admits the gate does not exist, and it does"
    );
    assert!(
        doc.contains("outbound_trace_drift"),
        "docs/observability.md must name the guard, so a reader can find what enforces \
         the claim it makes"
    );
    let counts = [
        format!("{} outbound", INJECTS.len()),
        format!("{} carry", EXEMPT.len()),
    ];
    for needle in &counts {
        assert!(
            doc.contains(needle.as_str()),
            "docs/observability.md does not carry the current count '{needle}'. The \
             tables in crates/sbproxy-observe/tests/outbound_trace_drift.rs moved and \
             the doc did not"
        );
    }
}

# MCP security coverage

*Last modified: 2026-08-17*

What the gateway enforces against the OWASP MCP Top 10 (MCP01:2025 through
MCP10:2025, currently in beta; the next revision is expected around October
2026, and this page states the edition so that revision lands as a diff
against named rows rather than a rewrite). Coverage levels are literal:
**full (config-reachable)** means the control is enforced in the MCP
request path once configured, with a named test; **partial** means enforced
with a named gap; **out of gateway scope** means the risk lives with the
tool server, the network, or the operator's own process, and a proxy
cannot own it. Almost everything below is off by default. The profile that
turns every "full (config-reachable)" and "partial" row on at once is
[`examples/mcp-governance/`](../examples/mcp-governance/); if a row below
reads as more than your own config does today, that example is what closes
the gap.

For the threat-by-threat narrative behind each row, see
[mcp-security.md](mcp-security.md). For the field-by-field config
reference, see [mcp.md](mcp.md) and
[mcp-gateway-guardrails.md](mcp-gateway-guardrails.md). Named tests below
are the pack's own end-to-end suite,
[`e2e/tests/mcp_governance_pack_e2e.rs`](../e2e/tests/mcp_governance_pack_e2e.rs),
unless otherwise noted.

## OWASP MCP Top 10 (2025, beta) mapping

| # | Risk | SBproxy control | Coverage |
|---|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | Upstream credentials are resolved by the gateway and attached on the way out; the model never holds them. `content_filters.secrets` (`off`/`warn`/`redact`/`block`, default `off`) scans tool-call arguments and results for credential shapes (`openai_key`, `anthropic_key`, `aws_access`, `github_token`, `slack_token`) before either reaches the wire, proven by `planted_secret_is_redacted_before_dispatch`. Gateway-issued inbound keys get TTL, rotation with a grace window, and revocation through the generic `key_management:` admin surface (see [key-management.md](key-management.md)); this is not MCP-specific machinery, it is the credential plane every origin shares. **Gap:** detection is a fixed regex/shape catalogue, not entropy-based, so a secret shaped like nothing on that list passes through unflagged; no entropy detector ships. | partial |
| MCP02 | Privilege Escalation via Scope Creep | `rbac_policies` is default-deny: a caller matching no rule is refused, so a tool added upstream never silently widens who can call it, proven by `ungranted_tool_is_refused_by_rbac`. `tool_quotas[]` caps how often a granted tool can be called; the `tool_allowlist` guardrail pins the callable surface for the whole origin; `tool_versioning`'s `block_unlocked: true` refuses a tool with no committed lockfile entry, which closes the specific case of a new tool showing up and being reachable before anyone reviewed it, proven by `unlocked_tool_is_blocked_by_the_version_gate`. **Gap:** grants do not expire. Time-boxed grants with renewal were scoped for this epic and are not shipped; a reviewed grant stays in force until an operator edits the policy by hand. | partial |
| MCP03 | Tool Poisoning | Tool contracts (`name`, `description`, `inputSchema`, `outputSchema`, `annotations`) are pinned by digest in a committed lockfile and re-checked on every catalog refresh; a changed, renamed, or removed tool is graded and either reported or blocked (`tool_versioning`, shipped pre-epic with its own test suite; see [tool-versioning.md](tool-versioning.md)). Every catalog refresh also reports concealed text (Unicode TAG blocks, bidirectional controls, zero-width characters) and static poisoning indicators (credential paths, model-directed instructions) in advertised tool text, on `sbproxy_mcp_concealed_text_findings_total` and `sbproxy_mcp_poison_indicators_total`. **Gap:** the digest gate is a real refusal; the concealed-text and poison-indicator reports are not. They are edge-triggered signals for a human or a SIEM rule, deliberately never a block, because a heuristic detector's false-positive cost is a catalog that stops working. | partial |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | Every `federated_servers[]` entry is a supply-chain decision: `egress` is deny-by-default per server, covering both an OpenAPI-backed server's REST calls and, since this epic, a plain `type: mcp` server's base connect over `streamable_http` or `sse`; every dial's outcome (allowed, denied, or ungated) is recorded at `GET /api/egress`, proven by `egress_denied_upstream_is_never_dialed`. Registry approval status (`status: draft \| approved \| deprecated`, plus operator-attested `approved_by`/`approved_at`) gates which servers are even reachable before any of that: `draft` is neither advertised nor callable, proven by `draft_server_tools_are_hidden_and_refused`. **Gap:** `stdio` servers spawn a local child process and sit outside egress control entirely; keeping the launched binary honest is a supply-chain problem this gateway does not reach. `approved_by`/`approved_at` are stored, never verified: they are a fact about your process, not one the gateway can witness. The `draft`-invisibility claim above carries the same known Code Mode listing exception MCP09 documents below: `GET /.well-known/mcp/codemode.ts` leaks a `draft` server's tool metadata into that one listing surface even though `tools/list` and `tools/call` correctly hide and refuse it. | partial |
| MCP05 | Command Injection & Execution | `argument_policies[]` evaluates a CEL or OPA-compatible Rego expression against the parsed tool-call arguments, after RBAC and JSON-Schema validation and before dispatch; the rule can only turn an already-passed allow into a refusal, never the reverse, and an expression that fails to evaluate denies fail-closed rather than passing silently. Proven in both engines: `argument_policy_cel_blocks_the_injection_shaped_call` and `argument_policy_rego_blocks_the_injection_shaped_call`. `result_policies[]` mirrors the same mechanism against the tool-call result. **Still yours:** the tool or server on the other end of the call owns final sanitization of whatever argument shape gets through. A rule you write narrows what reaches dispatch; it does not replace input validation inside the tool's own implementation, and the gateway has no opinion about which arguments matter for tools it did not write. | full (config-reachable) |
| MCP06 | Intent Flow Subversion | `flow` tracks two session-scoped labels the gateway can observe deterministically at the dispatch seam: `integrity` (`trusted` -> `tainted` on a read from outside `trusted_servers`) and `sensitive_touched` (sticky `true` on a read from `sensitive_servers` or a call to `sensitive_tools`), both most-restrictive-wins and never lowering within a session. The default rule, `two_of_three`, is Meta's Rule of Two: a session that is both tainted and has touched sensitive data is refused the moment it attempts a call matching `outbound_tools`, proven by `taint_then_outbound_is_refused_by_the_flow_guardrail`. This composes with the pre-existing `lethal_trifecta` session guardrail and the opt-in `dual_llm_quarantine` judge. **Honest framing:** `flow` is a deterministic, config-driven approximation of intent, not a semantic read of what a session actually did; it has real false positives, and naming which servers are trusted or sensitive is the operator's judgment call. `dual_llm_quarantine` is the probabilistic layer next to it: another model judging tool output, opt-in, with everything that implies about its own failure modes. | partial |
| MCP07 | Insufficient Authentication & Authorization | The 2026-07-28 transport's trust check runs before authentication, before any OAuth challenge, and before any catalog work; a request addressed to an authority the gateway does not serve is refused with an empty body (`modern_http`), and the pack's default posture refuses every call before any governance check runs when no credential is presented, proven by `unauthenticated_call_is_refused_before_any_governance_check`. RBAC is default-deny (see MCP02). Federated peers are downgrade-resistant: once a peer has demonstrated the modern protocol era or that it requires auth, a later contact that looks weaker is warned or refused (`federated_servers[].downgrade: warn \| block`), never silently accepted as the new normal. **Gap:** `stdio` transport has no equivalent trust check to run; it is a local child process, not a network peer, and hardening that surface is tracked as ongoing work rather than shipped here. A request that omits the modern era's evidence headers is classified as legacy and reaches authentication before the gateway refuses it, which costs an extra round-trip rather than a disclosure. | partial |
| MCP08 | Lack of Audit and Telemetry | Every governed decision emits an `mcp_governance_decision` record over `events:` (see [events.md](events.md)): a dispatched or refused `tools/call`; a `draft`-server, peer-downgrade, or content-filter decision on `resources/read` or `prompts/get`, `mcp.method.name` naming the method in place of a tool name neither carries; a tool-definition change against the lockfile; or a registry approval-status transition -- each carrying OTel GenAI/MCP semantic-convention field names, a salted arguments digest (verbatim on opt-in via `mcp_audit.capture_arguments`), and `sbproxy.evidence.seq`, a per-tenant gapless sequence number so a SIEM can prove it received every record in a range rather than trust that it did. `events.fail_closed: [mcp_governance_decision]` refuses the call rather than serving it with no evidence behind it when the record cannot be queued, proven by `fail_closed_refuses_the_call_when_the_sink_cannot_accept_the_record`, and the gapless property itself is proven by `governance_evidence_carries_a_gapless_per_tenant_sequence` (e2e) and `two_tenants_interleaved_under_concurrency_each_produce_a_gapless_run` (`crates/sbproxy-observe/src/evidence_seq.rs`). The `resources/read` and `prompts/get` records are best-effort: unlike a `tools/call` denial, a delivery failure there does not also refuse the call under `events.fail_closed`, proven by `wor_2384_resources_read_content_filter_block_emits_governance_evidence` (`crates/sbproxy-core/src/server/action_dispatch.rs`). See [Which records are tamper-evident](#which-records-are-tamper-evident-by-name) below for what this sequence covers and what it does not. | full (config-reachable) |
| MCP09 | Shadow MCP Servers | Registry approval status is the primary control: a server has to be named and marked `approved` (or left absent, which defaults to `approved` so existing configs are unaffected) before its tools are advertised or callable at all; `draft` hides and refuses them, proven by `draft_server_tools_are_hidden_and_refused`. Every dial this gateway makes is inventoried at `GET /api/egress` with an allowed/denied/ungated status, so a server nobody approved but that somehow got configured still leaves a record. **Honest framing:** this is a choke-point architecture, not a discovery feature, and it is the category where a proxy is weakest. The gateway cannot see traffic that bypasses it: an agent wired directly to an MCP server, off this gateway entirely, is invisible to every control on this page. Making the gateway the only route out is network design, not proxy configuration; see [threat-model.md](threat-model.md#trust-boundaries) for the trust-boundary framing that recipe depends on. **Known exception:** the Cloudflare Code Mode TypeScript listing (`GET /.well-known/mcp/codemode.ts`, see [cloudflare-code-mode.md](cloudflare-code-mode.md)) is generated from the full federation registry and currently leaks a `draft` server's tool metadata into that listing even though the same server's `tools/list` and `tools/call` correctly hide and refuse it. This is a known gap in the draft-invisibility claim above, scoped to that one listing surface, and is being closed separately. | partial |
| MCP10 | Context Injection & Over-Sharing | `content_filters` runs the same secret/PII detector catalogue against tool-call results, `resources/read`, and `prompts/get` responses that MCP01 runs against arguments, closing a real structural hole: an MCP origin writes its own response outside the generic HTTP `response_filter` phase, so the `pii:`/`dlp:` HTTP-path controls never see this traffic at all without this block. `result_policies[]` lets an operator write a CEL/Rego rule against the result document directly. Catalogs, sessions, and cross-tenant references are tenant-scoped by construction: a key policy or session id from one tenant resolves to nothing in another's, proven by `an_mcp_catalogue_is_reachable_only_from_its_own_tenant`, `a_session_presented_by_a_different_tenant_is_rejected`, and `two_tenants_each_validate_only_their_own_session` (`crates/sbproxy-extension/src/mcp/sessions.rs`, `crates/sbproxy-core/src/pipeline.rs`); a cross-tenant probe is audited (`mcp_inject_source_denied`, `mcp_session_tenant_mismatch`) rather than merely logged. Session establishment is capacity-bounded per tenant (256) and globally (4096) so one tenant cannot crowd another out of the session registry; saturation refuses `initialize` fail-closed with a governance evidence event and `sbproxy_mcp_session_registry_saturated_total`, proven by `a_mint_past_the_tenant_sub_cap_is_refused_while_other_tenants_are_unaffected` (`crates/sbproxy-extension/src/mcp/sessions.rs`). **Gap:** `content_filters` and `result_policies[]` are shape- and rule-based; neither understands your data model well enough to know, unprompted, that a given field belongs to a different tenant. | partial |

## Which records are tamper-evident, by name

The gapless `sbproxy.evidence.seq` on `mcp_governance_decision` (MCP08) is
not the same property as the hash-chained audit trail described in
[audit-log.md](audit-log.md), and the two cover different records. Stated
plainly, so "tamper-evident" is not read as one blanket guarantee:

- **Hash-chained, via `audit.sink: chain`:** transport-trust denials
  (`mcp_transport_denied`), cross-tenant session probes
  (`mcp_session_tenant_mismatch`), cross-tenant catalog probes
  (`mcp_inject_source_denied`), and session-registry saturation
  (`mcp_session_registry_saturated`) all land on the `security_audit`
  channel, which is chainable today.
- **Hash-chained, via `audit.config_path`:** a `federated_servers[]`
  approval-status edit (`draft` -> `approved`, an `approved_by` change)
  travels through the ordinary `config_audit` trail, which is chainable
  separately from the security chain.
- **Not hash-chained:** the `mcp_governance_decision` record itself, the
  interaction log MCP08 asks for, tool-call decisions, tool-definition
  changes, and registry-status transitions alike. It never joins either
  chain above. Its own tamper-evidence mechanism is the gapless per-tenant
  sequence number: a missing `sbproxy.evidence.seq` value is a detectable
  hole on the SIEM side, not a rewritable line in a file the gateway
  controls. Treat the two mechanisms as complementary rather than
  interchangeable: the chains prove a *security* or *config* record was
  not edited after the fact; the sequence proves a *governance decision*
  record was not dropped in transit.

## The three governance bets, and what proves each one

- **Gapless, tamper-evident evidence.** `sbproxy.evidence.seq` never skips
  a number for a tenant while emission is enabled, proven by
  `two_tenants_interleaved_under_concurrency_each_produce_a_gapless_run`
  (unit) and `governance_evidence_carries_a_gapless_per_tenant_sequence`
  (e2e). See [Which records are tamper-evident](#which-records-are-tamper-evident-by-name)
  above for exactly which records this covers.
- **Deterministic flow enforcement.** `flow`'s `two_of_three` rule refuses
  a session that is both tainted and sensitive-touched the moment it
  attempts an outbound call, proven red-first in the gate's own test suite
  and by `taint_then_outbound_is_refused_by_the_flow_guardrail` (e2e).
- **Definition pinning with re-approval.** Shipped ahead of this epic and
  cited here rather than rebuilt: a tool's contract is pinned by digest,
  movement is graded, and an unbumped violation is blocked or reported
  under its own long-running test suite (see
  [tool-versioning.md](tool-versioning.md)). The version gate specifically
  is re-proven in this pack by `unlocked_tool_is_blocked_by_the_version_gate`.

## See also

- [mcp-security.md](mcp-security.md) - the threat-by-threat writeup this
  table summarizes.
- [mcp.md](mcp.md) and [mcp-gateway-guardrails.md](mcp-gateway-guardrails.md)
  - the field-by-field configuration reference.
- [examples/mcp-governance/](../examples/mcp-governance/) - every row
  above marked "full (config-reachable)" or "partial", turned on at once,
  with a curl walkthrough.
- [events.md](events.md) - the `mcp_governance_decision` wire shape,
  fail-closed delivery, and retention.
- [audit-log.md](audit-log.md) - the hash-chained `security_audit` and
  `config_audit` trails referenced above.
- [threat-model.md](threat-model.md) - trust boundaries, including the
  choke-point assumption MCP09 depends on.
- [ai-gateway-security-coverage.md](ai-gateway-security-coverage.md) - the
  sibling coverage table for the OWASP LLM Top 10.

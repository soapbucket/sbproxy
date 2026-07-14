# SBproxy tool versioning

*Last modified: 2026-07-13*

An MCP tool has no version field. Its shape is a name, a description, an
`inputSchema`, and an `outputSchema`, and the only signal that any of them moved
is an opaque `notifications/tools/list_changed`. OpenAPI has semantic
versioning conventions for exactly this; MCP has nothing. So shipping a
breaking change to a tool means breaking every agent that calls it, at the
same moment, with no error they can act on.

The gateway closes that gap in two halves:

- **The rollout plane** publishes several versions of one tool at once,
  resolves the right version per consumer, routes or adapts each one, and
  retires old versions on a sunset date. This is how you ship `search` v2
  while every v1 caller keeps working.
- **The compatibility oracle** grades any change against semantic versioning
  and fails a version-bump check when a breaking change ships without a
  matching major bump. It is the MCP counterpart of `cargo-semver-checks` or
  `elm diff`, with checks a structural tool cannot do, because the consumer
  here is a model.

## Rolling out a new version

The `rollout` block under `tool_versioning` declares the published versions of
a tool, where each one lives, and who gets which:

```yaml
origins:
  "mcp.example.com":
    action:
      type: mcp
      federated_servers:
        - origin: "legacy.internal"
          prefix: legacy-api
        - origin: "new.internal"
          prefix: new-api
      tool_versioning:
        rollout:
          tools:
            search:
              versions:
                - version: "1.4.0"
                  server: legacy-api
                  sunset: "2026-10-01"
                - version: "2.0.0"
                  server: new-api
          pins:
            - principals:
                - team: checkout
              tools:
                search: "^1"
```

With that block live, `tools/list` advertises one `search` whose schema is the
version the consumer resolves to, plus `search_v1` and `search_v2` aliases
(aliases are on by default; set `aliases: false` per tool to hide them). A
`tools/call` on `search` routes to the resolved version's server; a call on
`search_v1` routes to the highest 1.x.

### How a consumer gets a version

Resolution walks a ladder, most specific first:

1. **Call**: a semver range in the request `_meta`, key
   `sbproxy.dev/version`. Wins over everything.
2. **Session**: a `{tool: range}` map declared once at `initialize` under
   `_meta` key `sbproxy.dev/tool_requirements`, held on the MCP session
   (requires `sessions.enabled`).
3. **Pin**: the first `pins` entry whose principal selector matches the
   authenticated caller. Selectors are the same shape as the RBAC
   `principals` rows; an empty selector list pins everyone. This is the rung
   that works with every current MCP client, because the operator controls
   it.
4. **Alias**: the version-suffixed catalogue name (`search_v1`), for clients
   that pick tools from the catalogue and cannot send `_meta`.
5. **Default**: the tool's `default:` version, else its highest.

Ranges are standard semver requirements (`^1`, `~1.4`, `>=1, <2`). Every
`tools/list` entry carries `_meta` with `sbproxy.dev/version` (what this
consumer resolved to), `sbproxy.dev/available` (every published version), and
`sbproxy.dev/sunset` when set, so a capable client can choose without any
operator involvement.

### Retiring the old upstream: adapters

While both upstreams run, versions route. Once the old server is gone, a
version can instead carry request/response adapters and be served off the new
upstream:

```yaml
versions:
  - version: "1.4.0"
    sunset: "2026-10-01"
    adapter:
      request: "js:adapters/search-v1.js"
      response: "js:adapters/search-v1.js"
    contract:
      name: search
      description: Search repositories
      inputSchema:
        type: object
        properties:
          q: { type: string }
        required: [q]
  - version: "2.0.0"
    server: new-api
```

The reference is `js:` plus a file path. The file defines `request(args)`
and/or `response(result)` and returns the transformed value; the same file
can serve both fields. A version with an adapter and no `server` dispatches
to the default version's server. The inline `contract` is what `tools/list`
advertises for the version once no live upstream serves it; without one the
gateway falls back to a live entry and skips the alias when none exists, so
it never advertises a schema it cannot honor. JavaScript is the supported
adapter runtime today.

An adapter failure fails the call with a typed JSON-RPC error (code
`-32098`) rather than passing the untranslated shape through: a silent
contract break is the exact thing this plane exists to prevent.

### Sunset

A version with a `sunset: YYYY-MM-DD` date is annotated as deprecated in the
catalogue (description suffix plus `_meta`), and every call it serves is
counted and logged. Past the date, `after_sunset: warn` (the default) keeps
serving; `after_sunset: block` fails calls with the sunset in the error.

Migration is observable on
`sbproxy_mcp_tool_version_calls_total{tool, version, via, deprecated}`: when
a version's traffic hits zero, it is safe to remove from the config. Results
served by the plane carry `_meta.sbproxy.dev/version` so a caller can always
tell which version answered.

RBAC, quotas, guardrails, and per-server timeouts apply to versioned calls
exactly as to any other: the gates run against the resolved server after the
version rewrite.

See `examples/mcp-tool-rollout/` for a runnable two-version configuration
with a pin and an adapter.

## Grading changes: the compatibility oracle

The second half is knowing when a change NEEDS a new version. The oracle
gives every tool a content digest and grades every change.

## What it produces

- **A contract digest.** A `sha256` over the RFC 8785 (JCS) canonical form of
  the tool's contract, so an equal digest means an equal contract no matter the
  key order.
- **A compatibility grade.** One of `none`, `patch`, `minor`, or `major`, taken
  as the most significant grade across three dimensions.
- **A version-bump verdict.** The declared bump compared against the computed
  grade, so an under-bump or a changed contract with no bump fails.

## The three dimensions

A change is compatible only if it holds on all three.

| Dimension | What it checks |
| --------- | -------------- |
| Structural | The input and output schema, graded by variance: input schemas are contravariant (a more restrictive input rejects old calls, so it is breaking), output schemas are covariant (removing or narrowing an output breaks consumers). |
| Behavioral | The response shape across versions, from a value-tolerant fingerprint. A shape change is breaking; a value-only change is not. |
| Description-semantics | Whether the natural-language description changed its meaning, selection intent, or side effects. This is the only model-dependent check, and it is opt-in. |

## Grades by change

| Change | Grade |
| ------ | ----- |
| Input: property removed, newly required, type narrowed, enum narrowed | major |
| Input: optional property added, enum widened | minor |
| Output: property removed, type narrowed | major |
| Output: property added | minor |
| Response shape changed under the same call | major |
| Description changed meaning or selection intent | major, flagged security-relevant |
| Description reworded but equivalent; title only | patch |

A description change that alters meaning is the rug-pull and tool-poisoning
class: a reworded tool that shifts selection or smuggles in an instruction. The
oracle grades it major and marks the finding security-relevant.

## The version-bump gate

Given the prior version, the newly declared version, and the computed grade, the
linter flags an under-bump (a breaking change shipped as a patch) or an
unchanged version over a changed contract. Over-bumping is fine. A clean run
passes; a violation fails with the tool and the grade it required, the same
ergonomic as a schema-diff gate in a pull request.

The baseline is a committed lockfile, one contract digest and semver per tool,
and the declared versions live in a registry the operator edits. The oracle
diffs the live tools against the lockfile and lints each declared bump.

## The description judge

The description-semantics dimension asks a model whether the meaning moved. The
oracle stays model-agnostic: it takes a judge you supply, so the gateway wires
its own provider stack rather than pinning a client. Supply more than one judge
to run a jury; agreement across their scores sets the confidence, and a split
jury returns needs-confirmation rather than a hard pass or fail. Without a
configured judge, the dimension is skipped and the verdict is structural and
behavioral only, so it never blocks on its own.

Judges are declared under the same `tool_versioning` block. Each one is a BYOK
OpenAI-compatible chat-completions endpoint; the bearer key comes from an
environment variable, never from config:

```yaml
tool_versioning:
  lockfile: "tool-versions.lock.yaml"
  mode: block
  judges:
    - endpoint: "https://api.openai.com/v1/chat/completions"
      api_key_env: OPENAI_API_KEY
      model: gpt-5-mini
      timeout: 5s
      budget_tokens: 100000
```

Judge calls are counted on the `sbproxy_judge_calls_total` family next to the
policy judge's spend, and each judge carries a token-equivalent budget so a
churning catalogue cannot drain it. A judge failure falls back to the
deterministic dimensions and records a `judge_error` verdict; a split jury
records `needs_confirmation` and leaves traffic alone even in block mode.

## The live gate

The `tool_versioning` block on the `mcp` action wires the oracle into the
gateway. At every catalogue refresh that actually changed the contract set,
the gateway diffs the live tools against the lockfile and lints each declared
bump:

```yaml
origins:
  "mcp.example.com":
    action:
      type: mcp
      tool_versioning:
        lockfile: "tool-versions.lock.yaml"
        mode: warn            # or block
        declared_versions:
          search: "1.1.0"
      federated_servers:
        - origin: "tools.internal"
```

`mode: warn` logs a `mcp.tool_versioning.violation` audit event and counts it
on `sbproxy_mcp_tool_compat_verdicts_total{grade, outcome}`. `mode: block`
also removes the violating tool from `tools/list` and fails its `tools/call`
with an error carrying the linter's detail. A changed tool with no entry in
`declared_versions` is linted as "no bump declared" against its lockfile
version.

The lockfile is read at refresh time, never at config compile. An unreadable
or invalid lockfile fails open: nothing is blocked, the gateway logs a loud
error, and the metric records `outcome="lockfile_error"`. Tools present in the
lockfile but missing from the live catalogue are reported as
`outcome="removed_tool"` and never block anything else.

See `examples/mcp-tool-versioning/` for a runnable configuration, including
a complete `tool-versions.lock.yaml` to copy the format from. The lockfile is
a committed YAML baseline: one entry per advertised tool carrying a declared
semver, a contract digest, and optionally the embedded contract itself. The
`contract` field is optional: a digest-only baseline still detects changes,
graded as at least a patch.

## Status

The oracle engine, the `sb.yml` gate, and the runtime enforcement ship today.

## Related

- [mcp.md](mcp.md) - the MCP gateway this grades tools for.

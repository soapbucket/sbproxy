# SBproxy tool versioning

*Last modified: 2026-06-30*

An MCP tool has no version field. Its shape is a name, a description, an
`inputSchema`, and an `outputSchema`, and the only signal that any of them moved
is an opaque `notifications/tools/list_changed`. So a tool can change under the
agents that call it with no error: a required argument gets renamed, an enum
value drops, a description is reworded and the model starts choosing a different
tool. The change ships quietly and shows up as a behavior regression later.

The compatibility oracle closes that gap at the gateway. It gives every tool a
content digest, grades a change against semantic versioning, and fails a
version-bump check when a breaking change ships without a matching major bump.
It is the MCP counterpart of `cargo-semver-checks` or `elm diff`, with two
checks a structural tool cannot do, because the consumer here is a model.

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

See `examples/mcp-tool-versioning/` for a runnable configuration.

## The CI gate

`sbproxy-mcp-drift` generates and checks lockfiles, so the same oracle that
guards the gateway can fail a pull request. Both flows take a `tools/list`
dump: the full JSON-RPC response, the bare result object, or a plain tools
array, from a file or stdin.

```bash
# Snapshot the live catalogue into a committed lockfile.
curl -s https://mcp.example.com/ -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
     | sbproxy-mcp-drift --lock-tools - --lockfile tool-versions.lock.yaml

# CI: fail the build on an under-bumped contract change.
curl -s https://mcp.example.com/ -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
     | sbproxy-mcp-drift --check-tools - --lockfile tool-versions.lock.yaml
```

`--check-tools` exits 0 when every tool is unchanged or every change carries
a covering bump, 1 when the only findings are new or removed tools, and 2 on
a version-bump violation, printing the tool and the grade it required.
Declared bumps come from `--declared versions.yaml` (a `tool: semver` map);
without it, changes are linted against the lockfile versions, meaning "no
bump declared". Regenerating a lockfile carries prior versions over for
existing tools, so a snapshot refresh never invents a bump.

## Status

The oracle engine, the `sb.yml` gate, the runtime enforcement, and the
lockfile CLI all ship today. The embedded `contract` field in the lockfile is
optional: a digest-only baseline still detects changes, graded as at least a
patch.

## Related

- [mcp.md](mcp.md) - the MCP gateway this grades tools for.
- [mcp-schema-drift.md](mcp-schema-drift.md) - CI schema-drift detection for
  converted MCP servers, which detects that a tool changed. Tool versioning
  grades the change and gates the bump.

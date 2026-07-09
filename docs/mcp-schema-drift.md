# MCP schema-drift detection
*Last modified: 2026-07-09*

Schema drift is the most-cited open problem in the API-to-MCP
space: when the upstream OpenAPI changes, MCP tools fail silently
with confident wrong answers, and no widely-adopted contract test
catches it. Teams hand-roll regeneration pipelines in CI and live
without a gate.

SBproxy ships `sbproxy-mcp-drift`, a CI-friendly CLI that diffs
two OpenAPI snapshots and classifies the changes by severity so
a pipeline can refuse to regenerate the MCP tool surface on a
breaking change without explicit operator opt-in.

The same CLI can also compare a consumer cassette against a live
MCP `tools/list` snapshot. That mode catches producer drift against
the contract a client actually relied on, rather than only against
the previous producer snapshot.

## Severity model

| Severity | What it means | Examples |
|---|---|---|
| **none** | identical specs | no change |
| **informational** | changes exist; none break callers | new operation added, description rewritten, required field made optional, enum widened |
| **breaking** | existing callers WILL break | operation removed, required field removed, type changed on a required field, enum narrowed |

The overall severity of a comparison is the max across every
classified change. The CLI maps it to an exit code:

| Severity | Exit code |
|---|---|
| `none` | `0` |
| `informational` | `1` |
| `breaking` | `2` |

## Usage

```bash
sbproxy-mcp-drift --previous prev.openapi.json --current cur.openapi.json
sbproxy-mcp-drift --previous prev.openapi.yaml --current cur.openapi.yaml --format json
sbproxy-mcp-drift --cassette session-ledger.ndjson --current-tools live-tools-list.json

# Lockfile modes: snapshot a tools/list dump into a committed lockfile,
# then gate CI on version-bump discipline against it. `-` reads stdin.
sbproxy-mcp-drift --lock-tools live-tools.json --lockfile tool-versions.lock.yaml
sbproxy-mcp-drift --check-tools live-tools.json --lockfile tool-versions.lock.yaml
```

OpenAPI inputs accept JSON or YAML. The `--lock-tools` / `--check-tools`
modes accept a `tools/list` JSON dump in any of three shapes: the full
JSON-RPC response, the bare result object, or a plain tools array.
Cassette mode accepts JSON, YAML,
or NDJSON session-ledger records and looks for:

* MCP `tools/list` result envelopes with a `tools` array.
* JSON-RPC `tools/call` requests with `params.name` and
  `params.arguments`.
* `session-ledger-v1` `tool_call` records with `tool_name` and
  `params`.

## CI gate

```bash
# Refuse to regenerate the MCP surface on a breaking change.
# The --accept-drift override below is a convention for YOUR
# regeneration pipeline, not a flag of sbproxy-mcp-drift itself;
# the tool only reports and sets the exit code.
if ! sbproxy-mcp-drift \
    --previous last-known.openapi.json \
    --current current.openapi.json ; then
    case $? in
        1) echo "informational drift; review and ack with your pipeline's --accept-drift if intentional" ;;
        2) echo "BREAKING drift; refusing to regenerate MCP surface" >&2 ; exit 1 ;;
    esac
fi
```

Cassette gate:

```bash
# Refuse deploy when a live MCP server no longer satisfies the
# consumer contract captured in a cassette.
sbproxy-mcp-drift \
  --cassette cassettes/customer-onboarding.ndjson \
  --current-tools snapshots/live-tools-list.json
```

## Change kinds

The JSON output's `kind` field is the closed-set vocabulary
downstream tooling keys off (defined in
`sbproxy_extension::mcp::schema_drift::DriftKind`):

| Kind | Severity | Description |
|---|---|---|
| `operation_added` | informational | new operation appeared |
| `operation_removed` | breaking | operation gone |
| `description_changed` | informational | description-only edit |
| `required_param_added` | breaking (when required) / informational (when optional) | new parameter |
| `required_param_removed` | breaking (was required) / informational (was optional) | parameter gone |
| `required_param_relaxed` | informational | required → optional |
| `required_param_type_changed` | breaking (required) / informational (optional) | type slug changed |
| `enum_narrowed` | breaking | dropped enum value(s) |
| `enum_widened` | informational | added enum value(s) |

Cassette mode uses a cassette-specific event vocabulary in
`sbproxy_extension::mcp::cassette_drift::CassetteDriftKind`:

| Kind | Severity | Description |
|---|---|---|
| `tool_added` | informational | live `tools/list` contains a tool absent from the cassette |
| `tool_removed` | breaking | a cassette tool is absent from live `tools/list` |
| `description_changed` | informational | tool description changed |
| `field_added` | informational or breaking | live schema added a field; breaking when the new field is required |
| `field_removed` | breaking | cassette field is absent from the live schema |
| `required_flipped` | informational or breaking | a field changed requiredness; optional to required is breaking |
| `type_changed` | informational or breaking | a field type slug changed |
| `enum_shrunk` | breaking | live enum dropped cassette values |
| `enum_widened` | informational | live enum gained values |

## Sample output

### Text (default)

```
overall severity: breaking
changes (2):
  [breaking]
    - param `color` enum narrowed: removed [`green`] (listWidgets)
  [informational]
    - operation `listWidgets` description changed (listWidgets)
```

### JSON

```json
{
  "severity": "breaking",
  "changes": [
    {
      "severity": "breaking",
      "operation": "listWidgets",
      "summary": "param `color` enum narrowed: removed [`green`]",
      "kind": "enum_narrowed"
    },
    {
      "severity": "informational",
      "operation": "listWidgets",
      "summary": "operation `listWidgets` description changed",
      "kind": "description_changed"
    }
  ]
}
```

### Cassette JSON

```json
{
  "cassette": "cassettes/customer-onboarding.ndjson",
  "severity": "breaking",
  "changes": [
    {
      "tool": "search",
      "field": "mode",
      "severity": "breaking",
      "kind": "enum_shrunk",
      "summary": "field `mode` enum shrunk on tool `search`: removed [`deep`]"
    }
  ]
}
```

Every cassette change can also be projected into an event payload via
`CassetteDriftReport::events()`. The event type is
`mcp.schema_drift.detected` and the payload includes `cassette`, `tool`,
optional `field`, `kind`, `severity`, and `summary`.

## What the diff covers today

* Operations: added / removed / description-only changes.
* Parameters: added / removed / required-toggle / type slug.
* Parameter enums: narrowed / widened.
* Cassette contracts: top-level MCP tool fields extracted from
  `inputSchema` plus observed `tools/call` argument keys.

Out of scope today (follow-ups):

* Deep schema diffs (`oneOf`, `$ref` chasing, `additionalProperties`).
* Request-body schema changes (this PR ships parameter-level
  diff only).
* Response-body schema changes.
* Nested MCP tool input diffs below the first object level.

## Library API

The CLI is a thin wrapper around
`sbproxy_extension::mcp::schema_drift`:

```rust
use sbproxy_extension::mcp::schema_drift::{diff_openapi, DriftSeverity};

let prev: serde_json::Value = serde_json::from_str(prev_json)?;
let cur: serde_json::Value = serde_json::from_str(cur_json)?;
let report = diff_openapi(&prev, &cur);
if report.severity == DriftSeverity::Breaking {
    // refuse to regenerate
}
```

Cassette mode is also available as a library API:

```rust
use sbproxy_extension::mcp::cassette_drift::{
    cassette_contract_from_value, diff_cassette_against_tools, tools_from_value,
};

let cassette_contract = cassette_contract_from_value("run.ndjson", &cassette_json);
let live_tools = tools_from_value(&tools_list_json);
let report = diff_cassette_against_tools(&cassette_contract, &live_tools);
for event in report.events() {
    // emit event to the audit/event sink
}
```

Wire it into the gateway's converted-MCP-server registration
path to emit an `mcp.schema_drift.detected` audit event when an
operator's registered spec changes hash; today that wire-up is
a small follow-up that consumes this PR's public API.

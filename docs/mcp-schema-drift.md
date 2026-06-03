# MCP schema-drift detection
*Last modified: 2026-06-03*

Schema drift is the most-cited open problem in the API-to-MCP
space: when the upstream OpenAPI changes, MCP tools fail silently
with confident wrong answers, and no widely-adopted contract test
catches it. Teams hand-roll regeneration pipelines in CI and live
without a gate.

SBproxy ships `sbproxy-mcp-drift`, a CI-friendly CLI that diffs
two OpenAPI snapshots and classifies the changes by severity so
a pipeline can refuse to regenerate the MCP tool surface on a
breaking change without explicit operator opt-in.

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
```

Both inputs accept JSON or YAML; the CLI sniffs the file with
`serde_json` first, then falls back to `serde_yaml`.

## CI gate

```bash
# Refuse to regenerate the MCP surface on a breaking change.
# Operator overrides with --accept-drift in the regeneration
# pipeline when the breaking change is intentional.
if ! sbproxy-mcp-drift \
    --previous last-known.openapi.json \
    --current current.openapi.json ; then
    case $? in
        1) echo "informational drift; review and ack with --accept-drift if intentional" ;;
        2) echo "BREAKING drift; refusing to regenerate MCP surface" >&2 ; exit 1 ;;
    esac
fi
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

## What the diff covers today

* Operations: added / removed / description-only changes.
* Parameters: added / removed / required-toggle / type slug.
* Parameter enums: narrowed / widened.

Out of scope today (follow-ups):

* Deep schema diffs (`oneOf`, `$ref` chasing, `additionalProperties`).
* Request-body schema changes (this PR ships parameter-level
  diff only).
* Response-body schema changes.

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

Wire it into the gateway's converted-MCP-server registration
path to emit an `mcp.schema_drift.detected` audit event when an
operator's registered spec changes hash; today that wire-up is
a small follow-up that consumes this PR's public API.

#!/usr/bin/env bash
#
# scripts/check-doc-drift.sh
#
# Guard against regression of provider-count, routing-strategy, and
# unimplemented-feature claims in user-facing docs. Code reality:
#
#   - crates/sbproxy-ai/data/ai_providers.yml has 70 entries.
#   - crates/sbproxy-ai/src/routing.rs defines 19 routing strategies
#     (RoundRobin, Weighted, FallbackChain, Random, LowestLatency,
#     LeastConnections, CostOptimized, TokenRate, LeastTokenUsage,
#     PrefixAffinity, Sticky, Race, PeakEwma, Cascade, CostQuality,
#     OutcomeAware, Headroom, ResetAware, SemanticRoute). TokenRate is
#     refused at config load (WOR-2233, superseded by LeastTokenUsage),
#     so 18 are actually selectable.
#   - crates/sbproxy-modules/src/action/routing/ ships two built-in
#     RoutingStrategy implementations: first-healthy and lora-aware.
#   - crates/sbproxy-observe/src/decision.rs defines 8 decision engines
#     (built_in, plugin, cel, lua, js, rego, wasm, proxy_wasm) and 18
#     decision events, so any documented cardinality product that
#     multiplies by the engine count uses 8, not 7.
#   - crates/sbproxy-security/ exposes crypto, hostfilter, ip, pii, ssrf,
#     and the optional headless_detect / agent_verify modules. There is
#     no certpin module: per-upstream SPKI pinning is not implemented
#     (WOR-166). Do not reintroduce the claim without code.
#
# The strings below previously appeared in docs and went stale. If any
# reappears, this check fails so the offending PR can fix the count
# before merge.
#
# Usage:
#   scripts/check-doc-drift.sh            # scan default targets, exit 1 on hit
#   scripts/check-doc-drift.sh --root .   # explicit repo root
#
# Exit codes:
#   0  no stale strings found
#   1  one or more stale strings found
#   2  invalid CLI usage

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,30p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Targets we actively police. Adding a new doc surface that should be
# guarded is a one-line addition here.
TARGETS=(
  "$ROOT_DIR/docs"
  "$ROOT_DIR/llms.txt"
  "$ROOT_DIR/README.md"
  "$ROOT_DIR/SECURITY.md"
  "$ROOT_DIR/CLAUDE.md"
)

# Substrings that must never reappear. Each entry is a fixed (-F) string
# so YAML / table escapes do not matter.
STALE_STRINGS=(
  "20 native"
  "9 routing strategies"
  "10 routing strategies"
  "ten routing strategies"
  "Ten routing strategies"
  # WOR-2564 added `semantic_route`, taking the selectable count from 17
  # to 18. Root `llms.txt` was still claiming 15 at the time, three
  # strategies behind, so both the count it carried and the one that was
  # true before this change join the list.
  "15 routing strategies"
  "17 routing strategies"
  "43 native providers"
  "one trivial built-in strategy"
  "36 OpenAI-compatible"
  "certpin"
  # WOR-2447: the decision-engine list and the cardinality product that
  # multiplies by it. `rego` landed with the multi-engine routing policy
  # and both went stale, which understated the label ceiling operators
  # size their Prometheus against. `DecisionEngine::ALL` has 8 variants
  # and `DecisionEvent::ALL` has 18, so the product is 18 x 8 x 7 = 1008.
  "18 x 7 x 7"
  "882 before tenancy"
  "\`js\`, \`wasm\`, \`proxy_wasm\`"
)

rc=0
for needle in "${STALE_STRINGS[@]}"; do
  for target in "${TARGETS[@]}"; do
    [ -e "$target" ] || continue
    if hits=$(grep -RFn --binary-files=without-match \
                 --include='*.md' --include='*.txt' \
                 -e "$needle" "$target" 2>/dev/null); then
      echo "stale string found: '$needle'" >&2
      echo "$hits" | sed 's/^/  /' >&2
      rc=1
    fi
  done
done

# Release-platform behavior. This reads the build matrix rather than matching
# prose, so a newly added or removed artifact forces an installation-doc review.
release_workflow="$ROOT_DIR/.github/workflows/release.yml"
expected_platforms=$(printf '%s\n' darwin_arm64 linux_amd64 linux_arm64)
actual_platforms=$(
  sed -n '/^[[:space:]]*matrix:/,/^[[:space:]]*steps:/p' "$release_workflow" |
    sed -n 's/^[[:space:]]*platform:[[:space:]]*//p' |
    sort
)
if [ "$actual_platforms" != "$expected_platforms" ]; then
  echo "release platform set changed; review installation documentation" >&2
  echo "  expected:" >&2
  echo "$expected_platforms" | sed 's/^/    /' >&2
  echo "  actual:" >&2
  echo "$actual_platforms" | sed 's/^/    /' >&2
  rc=1
fi

# The public images are assembled dynamically by the release workflow. They
# set only the binary entrypoint; operators must supply `serve -f ...`.
release_dockerfile=$(
  sed -n \
    '/cat > docker-ctx\/Dockerfile <<'\''EOF'\''/,/^[[:space:]]*EOF$/p' \
    "$release_workflow"
)
if ! printf '%s\n' "$release_dockerfile" |
     grep -Fq 'ENTRYPOINT ["/usr/local/bin/sbproxy"]'; then
  echo "published image entrypoint changed; review Docker documentation" >&2
  rc=1
fi
if printf '%s\n' "$release_dockerfile" | grep -Eq '^[[:space:]]*CMD[[:space:]]'; then
  echo "published image now has a default command; review Docker documentation" >&2
  rc=1
fi

# The generated schema covers the typed envelope but intentionally leaves
# module payloads and most objects open. Test the artifact's behavior directly.
schema="${SBPROXY_DOC_DRIFT_SCHEMA:-$ROOT_DIR/schemas/sb-config.schema.json}"
if ! python3 - "$schema" <<'PY'
import json
import sys

problems = []


def require(condition, message):
    if not condition:
        problems.append(message)


try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        document = json.load(handle)
    definitions = document["definitions"]
    origin = definitions["RawOriginConfig"]
    proxy = definitions["ProxyServerConfig"]
    origin_properties = origin["properties"]
    proxy_properties = proxy["properties"]
except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
    print(f"cannot inspect generated schema: {error}", file=sys.stderr)
    raise SystemExit(1)

opaque_keywords = ("type", "$ref", "oneOf", "anyOf", "allOf", "properties")
for field in ("action", "authentication"):
    payload = origin_properties.get(field)
    require(isinstance(payload, dict), f"origin {field} schema is missing")
    if isinstance(payload, dict):
        typed_keywords = [key for key in opaque_keywords if key in payload]
        require(
            not typed_keywords,
            f"origin {field} is no longer opaque; found {', '.join(typed_keywords)}",
        )

for field in ("policies", "transforms"):
    payload = origin_properties.get(field)
    require(isinstance(payload, dict), f"origin {field} schema is missing")
    if isinstance(payload, dict):
        require(payload.get("type") == "array", f"origin {field} is not an array")
        require(
            payload.get("items") is True,
            f"origin {field} items are no longer an opaque schema boundary",
        )

# The root stays open for the v1 flat-file compatibility promise; the
# proxy and origin envelopes are closed since WOR-1140 so a misspelled
# key fails config load instead of silently dropping. A schema that
# reopens one of them is a regression this check now catches.
require(isinstance(document, dict), "root schema is not an object")
if isinstance(document, dict):
    require(
        document.get("additionalProperties", True) is True,
        "root schema is no longer open; the v1 flat-file promise needs it",
    )
for name, typed_object in (
    ("proxy", proxy),
    ("origin", origin),
):
    require(isinstance(typed_object, dict), f"{name} schema is not an object")
    if isinstance(typed_object, dict):
        require(
            typed_object.get("additionalProperties", True) is False,
            f"{name} schema is open again; unknown keys must fail config load (WOR-1140)",
        )

require(
    "authentication" in origin_properties and "auth" not in origin_properties,
    "origin authentication/auth alias boundary changed",
)
require(
    "session" in origin_properties and "session_config" not in origin_properties,
    "origin session/session_config alias boundary changed",
)
require(
    "l2_cache_settings" in proxy_properties and "l2_cache" not in proxy_properties,
    "proxy l2_cache_settings/l2_cache alias boundary changed",
)

if problems:
    for problem in problems:
        print(problem, file=sys.stderr)
    raise SystemExit(1)
PY
then
  echo "generated schema boundaries changed; review JSON Schema documentation" >&2
  rc=1
fi

if [ "$rc" -eq 0 ]; then
  echo "doc-drift: ok"
fi

exit "$rc"

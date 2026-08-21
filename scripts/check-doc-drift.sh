#!/usr/bin/env bash
#
# scripts/check-doc-drift.sh
#
# Guard against regression of provider-count, routing-strategy, and
# unimplemented-feature claims in user-facing docs. Code reality:
#
#   - crates/sbproxy-ai/data/ai_providers.yml is the provider catalog.
#     Its size is read at check time rather than written down here, so
#     this comment cannot be the thing that goes stale (WOR-2627).
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
      # Through the Usage and exit-code blocks. The window was 30 lines
      # and the header outgrew it, so --help stopped before the usage it
      # exists to print.
      sed -n '1,40p' "$0"
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
  # WOR-2627: MIGRATION.md was outside every scan here, so the one page
  # still claiming a "90+ AI provider catalog" was the one page nothing
  # read. It is buyer-facing upgrade guidance and drifts like the rest.
  "$ROOT_DIR/MIGRATION.md"
)

# `docs/llms-full.txt` is a generated corpus: `regen-llms-full.sh`
# concatenates README.md, MIGRATION.md, CHANGELOG.md, and docs/*.md, and
# the repo convention (CLAUDE.md, "Provider catalog", point 4) refreshes
# it at release prep rather than on feature branches, so it lags its own
# sources by design.
#
# It stays in the fixed-string scan below, which covered it before the
# derived check existed and passed. What it is out of is the derived
# provider-count check, and the reason is CHANGELOG.md: the changelog is
# not a scan target, its historical entries are correct as history, and
# the corpus embeds them. `docs/llms-full.txt:3257` ("66 hosted
# providers") and `:3672` ("66 native AI providers") come straight from
# `CHANGELOG.md:2905` and `:3320`. Holding those to today's catalog
# would be asking history to change. The consequence, stated plainly: a
# stale count that reaches the corpus only through CHANGELOG.md is
# policed by nothing here.
GENERATED_CORPUS="llms-full.txt"

# Fixed strings the corpus is allowed to carry until the next release
# regen, because they were fixed in a source page on a branch and the
# corpus has not been rebuilt since. Audited below: an entry that stops
# matching is an error, so the regen drops it rather than leaving a
# standing exemption behind.
#
# One record per line, `needle :: reason`, so the scan and the audit
# cannot disagree about what is exempt.
CORPUS_LAG=(
  "90+ AI provider :: MIGRATION.md carried this from the initial commit and WOR-2627 fixed it there; the corpus still embeds the pre-fix page"
)
corpus_lag_reason() {
  local entry
  for entry in "${CORPUS_LAG[@]}"; do
    if [ "${entry%% :: *}" = "$1" ]; then
      printf '%s' "${entry#* :: }"
      return 0
    fi
  done
  return 1
}
corpus_lag_seen=""

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
  # WOR-2627: MIGRATION.md claimed this from the initial commit and no
  # scan ever covered the file. The derived check below is what stops
  # the next one; this entry stops this one coming back.
  "90+ AI provider"
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
    hits=$(grep -RFn --binary-files=without-match \
              --include='*.md' --include='*.txt' \
              -e "$needle" "$target" 2>/dev/null) || continue
    if lag=$(corpus_lag_reason "$needle"); then
      corpus_hits=$(printf '%s\n' "$hits" | grep -F "/$GENERATED_CORPUS:") || corpus_hits=""
      if [ -n "$corpus_hits" ]; then
        corpus_lag_seen="$corpus_lag_seen|$needle|"
        echo "generated corpus lags on '$needle' ($lag)" >&2
        printf '%s\n' "$corpus_hits" | sed 's/^/  /' >&2
      fi
      hits=$(printf '%s\n' "$hits" | grep -Fv "/$GENERATED_CORPUS:") || hits=""
    fi
    if [ -n "$hits" ]; then
      echo "stale string found: '$needle'" >&2
      printf '%s\n' "$hits" | sed 's/^/  /' >&2
      rc=1
    fi
  done
done

# Reverse audit on the lag list, the same way NOT_OUR_CATALOG is audited
# below. A lag entry that matches nothing means the regen happened, so
# the entry is now a standing exemption for a string that is gone.
for entry in "${CORPUS_LAG[@]}"; do
  needle="${entry%% :: *}"
  case "$corpus_lag_seen" in
    *"|$needle|"*) ;;
    *)
      echo "docs/$GENERATED_CORPUS no longer contains '$needle'; drop it from" >&2
      echo "  CORPUS_LAG, the corpus was regenerated and the exemption now" >&2
      echo "  covers nothing" >&2
      rc=1
      ;;
  esac
done

# Provider-count claims, derived from the catalog rather than listed.
#
# The list above can only ever catch a number somebody already noticed
# was wrong, which is how MIGRATION.md carried "90+" from the initial
# commit through the catalog's growth to 43 and its settling at 72
# without a single lane objecting. This reads
# `crates/sbproxy-ai/data/ai_providers.yml` and holds the docs to it, so
# the next provider added turns every page that was not updated with it
# red. That is CLAUDE.md's "update the hardcoded provider count
# everywhere" step, enforced instead of remembered.
#
# What it holds, exactly:
#
#   - Every digit-form provider total: a number followed by an optional
#     qualifier and the noun `provider`/`providers`, anywhere in a
#     scanned document, against the catalog's entry count.
#   - The wire-format breakdown of that total ("66 of the 72 catalog
#     entries", "3 custom-format entries"), against the catalog's
#     `format:` values, but only on a line that already carries a
#     policed total. That scope is what keeps it off the dozen unrelated
#     "N entries" phrases in docs/, and it is a real limit: a breakdown
#     sentence moved onto its own line stops being read. The blindness
#     is reported rather than assumed away, by the audit at the end that
#     fails if no breakdown claim matches anywhere.
#
# What it does not hold:
#
#   - Word-form counts ("seventy-two providers"). Those are the fixed
#     string list's job.
#   - Which group a bare "N entries" names. `66 entries` is checked
#     against the set of group sizes, so it catches the drift that
#     matters (add an OpenAI provider and 66 stops being any group's
#     size) but would not catch a translator count written where a
#     custom count belongs while both happen to be 3.
#   - Anything reaching `docs/llms-full.txt` only through CHANGELOG.md;
#     see the GENERATED_CORPUS note above.
if ! python3 - "$ROOT_DIR" "$GENERATED_CORPUS" "${TARGETS[@]}" <<'PY'
import gzip
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
generated_corpus = sys.argv[2]
targets = [Path(argument) for argument in sys.argv[3:]]

problems: list[str] = []

catalog = root / "crates" / "sbproxy-ai" / "data" / "ai_providers.yml"
embedded = root / "crates" / "sbproxy-ai" / "data" / "ai_providers.yml.gz"
try:
    catalog_bytes = catalog.read_bytes()
    embedded_bytes = embedded.read_bytes()
except OSError as error:
    print(f"cannot read the provider catalog: {error}", file=sys.stderr)
    raise SystemExit(1)

# The catalog, counted the way serde counts it.
#
# This used to be `len(re.findall(rb"^  - name:", ...))`, justified by a
# comment claiming the shape was "pinned from the other side" by
# `sbproxy_ai::providers::tests::embedded_catalog_matches_published_counts`.
# It is not: that test pins the count and the format split, never the
# key order or the indent. YAML mappings are unordered and
# `YamlProvider` is a plain derive, so an entry written
# `- display_name: NewCo` / `  name: newco` deserializes fine and the
# regex misses it. The two counters then disagree by one, and this
# script's message accuses the prose ("claims '73 native providers' but
# the catalog has 72"), which sends the next person to edit correct docs
# back to a wrong number.
#
# So count what serde counts: items in the `providers:` sequence, each
# of which must carry a `name` key. A structural walk rather than a YAML
# parse because this runs in lanes with no third-party packages, and an
# item without a `name` is reported rather than skipped, because serde
# would refuse it and a silent divergence is the bug above.
def read_catalog(text: str) -> tuple[int, list[str]]:
    """`(provider count, format of each provider)`, from the sequence."""
    formats: list[str] = []
    count = 0
    in_sequence = False
    pending_name = False
    for number, line in enumerate(text.splitlines(), start=1):
        if not in_sequence:
            if line.rstrip() == "providers:":
                in_sequence = True
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        item = re.match(r"^ {2}- (?P<first>\S.*)$", line)
        if item is not None:
            if count and not pending_name:
                problems.append(
                    f"{catalog}: the provider entry before line {number} has no "
                    "`name:`; serde would refuse the catalog and this check "
                    "would miscount it"
                )
            count += 1
            pending_name = False
            body = item.group("first")
        elif line.startswith("    "):
            body = line.strip()
        elif line.startswith(" "):
            continue
        else:
            # Back to column zero: the sequence ended.
            break
        if re.match(r"^name:\s*\S", body):
            pending_name = True
        matched = re.match(r"^format:\s*(?P<format>\S+)\s*$", body)
        if matched is not None:
            formats.append(matched.group("format"))
    if count and not pending_name:
        problems.append(
            f"{catalog}: the last provider entry has no `name:`; serde would "
            "refuse the catalog and this check would miscount it"
        )
    return count, formats


provider_count, provider_formats = read_catalog(catalog_bytes.decode("utf-8"))
if provider_count == 0:
    print(
        f"no providers parsed out of {catalog}; the catalog's shape changed "
        "and this check is now blind",
        file=sys.stderr,
    )
    raise SystemExit(1)
if len(provider_formats) != provider_count:
    # `format` carries no `#[serde(default)]`, so every entry has one or
    # the catalog does not deserialize. A count that disagrees means
    # this walk read the file differently from serde, and the breakdown
    # below would be derived from a partial read.
    for problem in problems:
        print(problem, file=sys.stderr)
    print(
        f"{provider_count} providers parsed out of {catalog} but "
        f"{len(provider_formats)} carry a `format:`; the wire-format "
        "breakdown below would be derived from a partial read",
        file=sys.stderr,
    )
    raise SystemExit(1)

# The published breakdown: OpenAI-format passthroughs, the in-tree
# translators (anthropic, google, bedrock), and the custom-shape
# entries. `CATALOG_FORMAT_SPLIT` in
# `crates/sbproxy-ai/src/providers/mod.rs` is the code half of the same
# claim; this is the prose half.
format_counts = {name: provider_formats.count(name) for name in set(provider_formats)}
openai_count = format_counts.get("openai", 0)
custom_count = format_counts.get("custom", 0)
translator_count = sum(
    format_counts.get(name, 0) for name in ("anthropic", "google", "bedrock")
)
group_counts = {openai_count, custom_count, translator_count} | {
    value for value in format_counts.values()
}

# Only the `.gz` is `include_bytes!`d into the binary. An edit to the
# `.yml` that never gets recompressed ships a catalog nothing runs, and
# leaves this check reading a file the product does not use.
if gzip.decompress(embedded_bytes) != catalog_bytes:
    problems.append(
        "ai_providers.yml.gz does not decompress to ai_providers.yml; "
        "regenerate it with "
        "`gzip -9 -n -c crates/sbproxy-ai/data/ai_providers.yml "
        "> crates/sbproxy-ai/data/ai_providers.yml.gz`"
    )

# A number attached to a provider noun. Digits only: word-form claims
# ("seventy-two providers") are the fixed-string list's job.
CLAIM = re.compile(
    r"(?P<count>\d+)\s*(?:\+|-plus)?[- ]"
    r"(?:(?:native|hosted|LLM|AI|model|in-tree|supported|OpenAI-compatible)[- ])*"
    r"providers?\b",
    re.IGNORECASE,
)

# The wire-format breakdown of the total, as four pages publish it:
# "66 of the 72 catalog entries", "66 entries are OpenAI-format
# passthrough", "3 custom-format entries", "3 are custom-shape entries".
#
# Scoped to lines that already carry a policed provider total, which is
# where every breakdown claim in the tree sits and is what keeps this
# off the twelve unrelated "N entries" phrases elsewhere in docs/ (LRU
# sizes, cache floors, 402 challenge entries). Anything the scope drops
# is stated in the header above.
BREAKDOWN = re.compile(
    r"(?P<count>\d+)(?:\s+of the\s+(?P<total>\d+))?"
    r"\s+(?:[\w`'-]+\s+){0,3}entries\b"
)
breakdown_claims = 0

# Counts that are correctly not ours. Keyed on the exact phrase so a
# reworded claim loses its exception and gets policed again, and audited
# below so an exception that stops matching anything is reported rather
# than quietly covering nothing.
NOT_OUR_CATALOG: dict[tuple[str, str], str] = {
    ("docs/comparison.md", "100+ providers"): "LiteLLM's catalog, in the comparison table",
    ("docs/comparison.md", "100+ native providers"): "LiteLLM's catalog, in the prose above the table",
    ("docs/comparison.md", "100+ LLM providers"): "LiteLLM's catalog, in the LiteLLM section",
    ("docs/admin-api-reference.md", "10 provider"): (
        "a sample-size floor for a latency estimate, not a catalog size: "
        "'inactive until at least 10 provider attempts contribute'"
    ),
}
used: set[tuple[str, str]] = set()

DOC_SUFFIXES = (".md", ".txt", ".html")


def documents() -> list[Path]:
    found: list[Path] = []
    for target in targets:
        if target.is_dir():
            found.extend(
                path
                for path in sorted(target.rglob("*"))
                if path.is_file() and path.suffix in DOC_SUFFIXES
            )
        elif target.is_file() and target.suffix in DOC_SUFFIXES:
            found.append(target)
    return [path for path in found if path.name != generated_corpus]


for path in documents():
    # `--root .` makes every path relative already, and older pathlib
    # refuses `relative_to('.')`. The display name is cosmetic, so fall
    # back rather than fail the lane over it.
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    for number, line in enumerate(text.splitlines(), start=1):
        ours = False
        for match in CLAIM.finditer(line):
            key = (relative, match.group(0))
            if key in NOT_OUR_CATALOG:
                used.add(key)
                continue
            ours = True
            if int(match.group("count")) != provider_count:
                problems.append(
                    f"{relative}:{number}: claims '{match.group(0)}' but the "
                    f"catalog has {provider_count} providers"
                )
        if not ours:
            continue
        for match in BREAKDOWN.finditer(line):
            breakdown_claims += 1
            phrase = match.group(0)
            count = int(match.group("count"))
            total = match.group("total")
            if total is not None and int(total) != provider_count:
                problems.append(
                    f"{relative}:{number}: claims '{phrase}' but the catalog "
                    f"has {provider_count} entries"
                )
            if "custom" in phrase.lower():
                if count != custom_count:
                    problems.append(
                        f"{relative}:{number}: claims '{phrase}' but the "
                        f"catalog has {custom_count} custom-format entries"
                    )
            elif total is not None:
                # `N of the M catalog entries`: N names one wire-format
                # group out of the whole.
                if count not in group_counts:
                    problems.append(
                        f"{relative}:{number}: claims '{phrase}' but no "
                        f"wire-format group in the catalog has {count} "
                        f"entries (openai {openai_count}, translators "
                        f"{translator_count}, custom {custom_count})"
                    )
            elif count not in group_counts and count != provider_count:
                problems.append(
                    f"{relative}:{number}: claims '{phrase}' but the catalog "
                    f"has {provider_count} entries split "
                    f"{openai_count}/{translator_count}/{custom_count} "
                    "(openai/translators/custom)"
                )

for key in sorted(NOT_OUR_CATALOG):
    if key not in used:
        problems.append(
            f"{key[0]} no longer contains '{key[1]}'; drop the "
            "NOT_OUR_CATALOG exception, it is covering nothing"
        )

# The breakdown half of this check reads a phrasing, so it goes blind if
# the phrasing changes. Say so rather than pass silently: four pages
# publish the split today and finding none of them means the regex above
# stopped matching, not that the claims went away.
if breakdown_claims == 0:
    problems.append(
        "no wire-format breakdown claim matched anywhere in the scanned docs; "
        "the pages that publish the split were reworded and this half of the "
        "check is now blind. Update BREAKDOWN in scripts/check-doc-drift.sh"
    )

if problems:
    for problem in problems:
        print(problem, file=sys.stderr)
    raise SystemExit(1)
PY
then
  echo "provider-count claims disagree with the shipped catalog" >&2
  rc=1
fi

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

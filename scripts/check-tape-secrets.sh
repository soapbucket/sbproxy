#!/usr/bin/env bash
# Refuse a VHS tape that would render a live credential into a committed GIF.
#
# # Why this exists
#
# `docs/assets/use-case-own-openrouter.gif` shipped with a full virtual-key
# token rendered in plaintext, and `ai-dynamic-keys.gif` shipped with two
# more. Each came from a tape that piped a freshly minted token straight to
# the terminal, which is the natural thing to write: the demo's whole point
# is that the plaintext token comes back exactly once, so showing it reads
# like showing the feature.
#
# A GIF is the worst place for that to happen. Nothing greps it, no secret
# scanner reads it, and it survives every later edit to the doc around it.
# The tape is the only place a check can see the intent, so this reads
# tapes rather than assets.
#
# # What it looks for
#
# A tape line that both mints or rotates a credential and prints the
# secret half of the response. The public half (`key_id`, `name`,
# `status`, `grace_expires_at`) is fine and is most of what these demos
# should show.
#
# The fix is never to delete the demo. Truncate: `.token[0:20] +
# "...REDACTED"` in a `jq` filter, or `${TOKEN:0:20}...REDACTED` in a
# shell echo. A reader still learns the shape and that it arrives once.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail=0

for tape in docs/tapes/*.tape; do
  [ -e "$tape" ] || continue

  # Only lines VHS actually types into the terminal can render anything.
  typed="$(grep -n '^Type ' "$tape" || true)"
  [ -n "$typed" ] || continue

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    lineno="${line%%:*}"
    body="${line#*:}"

    # A redacted line is the fixed shape and is what we want to see.
    case "$body" in
      *REDACTED*) continue ;;
    esac

    # Only a command's OUTPUT can leak. VHS renders the characters it
    # types, so a shell variable inside the typed text shows as the
    # literal `$TOKEN`: `-H "Authorization: Bearer $TOKEN"` is safe and
    # is how these demos should use a token after minting it.
    #
    # Two shapes put the value on screen:
    #   1. a `jq` filter emitting `token` whose output is not captured
    #      by a `$(...)` assignment, and
    #   2. `echo` of a token-bearing variable.
    leaks=0

    # Strip command substitutions first: whatever runs inside one is
    # captured into a variable rather than printed.
    uncaptured="$(printf '%s' "$body" | sed 's/\$([^)]*)//g')"

    case "$uncaptured" in
      *'{token,'*|*'{token}'*|*'{token '*|*'-r .token'*|*'-r ".token"'*) leaks=1 ;;
    esac
    case "$uncaptured" in
      *echo*'$TOKEN'*|*echo*'${TOKEN}'*|*echo*'$SECRET'*|*echo*'$PASSWORD'*) leaks=1 ;;
    esac

    if [ "$leaks" -eq 1 ]; then
      echo "$tape:$lineno prints a credential into the recorded GIF:" >&2
      echo "    ${body:0:160}" >&2
      fail=1
    fi
  done <<< "$typed"
done

if [ "$fail" -ne 0 ]; then
  cat >&2 <<'EOF'

Truncate the value rather than removing the demo. A reader should still
see that a plaintext token comes back once, and see its shape:

  jq '{token: (.token[0:20] + "...REDACTED"), key_id: .key.key_id}'
  echo "team-payments: ${TOKEN:0:20}...REDACTED"

Re-record the affected tape afterwards, because the committed GIF still
holds the old value until it is regenerated:

  scripts/record-tapes.sh <name>
EOF
  exit 1
fi

echo "tape secrets: ok ($(ls docs/tapes/*.tape 2>/dev/null | wc -l | tr -d ' ') tapes)"

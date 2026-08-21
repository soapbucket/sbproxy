#!/usr/bin/env bash
#
# End-to-end fixtures for the changelog fragment guard.
#
# `changelog-fragments.py --self-test` covers the parser and the
# assembler in process. It cannot cover the half that decides whether
# this branch edited CHANGELOG.md, because that half reads git, and the
# git it would read is this repository's own history: a fixture there
# would either pass for the wrong reason or fail whenever someone's
# branch happened to touch the file.
#
# So this builds throwaway repositories instead, one per case, and
# asserts the exit status. Every case below is a shape that has to keep
# working:
#
#   1. a branch that adds only a fragment                  -> pass
#   2. a branch that appends an entry under [Unreleased]   -> fail
#   3. a branch that edits a RELEASED section, no fragment -> fail
#   4. a release cut: assemble, which deletes fragments    -> pass
#   5. a branch that adds a fragment AND hand-appends      -> fail
#
# Case 4 is the one worth having a test for. The exemption that lets a
# release commit edit CHANGELOG.md is "the same diff also touches
# docs/.changes/", which holds only because assembling deletes the
# fragments it consumed. If assembly ever stopped deleting them, the
# release cut would start failing its own gate, and it would find that
# out during a release.
#
# Case 5 is the other one: it is the evasion. Rule 3 alone lets it
# through, and the [Unreleased] placeholder comparison is what stops it.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/changelog-fragments.py"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0

# A repository with one released section, the placeholder, and one
# committed fragment, on `main`, with `origin/main` pointing at it.
new_repo() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir/scripts" "$dir/docs/.changes"
  cp "$SCRIPT" "$dir/scripts/changelog-fragments.py"

  python3 - "$dir" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "cf", root / "scripts" / "changelog-fragments.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
(root / "CHANGELOG.md").write_text(
    "# Changelog\n\n## [Unreleased]\n\n"
    + module.PLACEHOLDER
    + "\n\n## [1.0.0] - 2026-01-01\n\n### Added\n\n- The first one.\n"
)
(root / "docs" / ".changes" / "20260820-seed.json").write_text(
    '{\n  "type": "fixed",\n  "message": "A seeded change."\n}\n'
)
PY

  git -C "$dir" init -q -b main
  git -C "$dir" config user.email t@example.com
  git -C "$dir" config user.name t
  git -C "$dir" add -A
  git -C "$dir" commit -qm base
  # A real branch diffs against origin/main. Give the fixture one that
  # resolves without a network by pointing the remote-tracking ref at
  # the base commit.
  git -C "$dir" update-ref refs/remotes/origin/main HEAD
  git -C "$dir" checkout -qb topic
}

expect() {
  local name="$1" want="$2" dir="$3"
  local got=0
  ( cd "$dir" && python3 scripts/changelog-fragments.py --check ) >"$work/out" 2>&1 || got=$?
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: $name: expected exit $want, got $got" >&2
    sed 's/^/    /' "$work/out" >&2
    failures=$((failures + 1))
    return
  fi
  echo "ok: $name"
}

# 1. A fragment and nothing else.
d="$work/case1"
new_repo "$d"
printf '{\n  "type": "added",\n  "message": "A new thing."\n}\n' \
  > "$d/docs/.changes/20260821-new-thing.json"
git -C "$d" add -A
git -C "$d" commit -qm "add fragment"
expect "a fragment alone passes" 0 "$d"

# 2. An entry appended under [Unreleased], the tax this exists to remove.
d="$work/case2"
new_repo "$d"
python3 - "$d" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1]) / "CHANGELOG.md"
text = path.read_text().replace(
    "\n## [1.0.0]", "\n### Added\n\n- Appended by hand.\n\n## [1.0.0]"
)
path.write_text(text)
PY
git -C "$d" add -A
git -C "$d" commit -qm "append by hand"
expect "an appended [Unreleased] entry fails" 1 "$d"

# 3. A released section edited with no fragment in the diff. Refused for
#    the message rather than the content: the author is in the file, and
#    this is where they learn there is another way in.
d="$work/case3"
new_repo "$d"
python3 - "$d" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1]) / "CHANGELOG.md"
path.write_text(path.read_text().replace("The first one.", "The first one, typo fixed."))
PY
git -C "$d" add -A
git -C "$d" commit -qm "typo"
expect "a bare CHANGELOG.md edit fails" 1 "$d"

# 4. A release cut. Assembly deletes the fragments it consumed, so the
#    same diff touches docs/.changes/ and the exemption applies.
d="$work/case4"
new_repo "$d"
( cd "$d" && python3 scripts/changelog-fragments.py --release 1.1.0 --date 2026-02-02 ) >/dev/null
git -C "$d" add -A
git -C "$d" commit -qm "release 1.1.0"
expect "a release cut passes" 0 "$d"
if ! grep -q '^## \[1.1.0\] - 2026-02-02$' "$d/CHANGELOG.md"; then
  echo "FAIL: release cut wrote no version heading" >&2
  failures=$((failures + 1))
fi
if ! grep -q 'A seeded change.' "$d/CHANGELOG.md"; then
  echo "FAIL: release cut dropped the fragment's message" >&2
  failures=$((failures + 1))
fi
if [ -e "$d/docs/.changes/20260820-seed.json" ]; then
  echo "FAIL: release cut left its fragment behind" >&2
  failures=$((failures + 1))
fi
if ! grep -q '^## \[1.0.0\] - 2026-01-01$' "$d/CHANGELOG.md"; then
  echo "FAIL: release cut disturbed an already released section" >&2
  failures=$((failures + 1))
fi

# 5. The evasion: a fragment satisfies the diff rule, and the hand-written
#    [Unreleased] entry rides along. The placeholder comparison is the
#    only thing between this and a green gate.
d="$work/case5"
new_repo "$d"
printf '{\n  "type": "added",\n  "message": "A new thing."\n}\n' \
  > "$d/docs/.changes/20260821-new-thing.json"
python3 - "$d" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1]) / "CHANGELOG.md"
text = path.read_text().replace(
    "\n## [1.0.0]", "\n### Added\n\n- Appended by hand anyway.\n\n## [1.0.0]"
)
path.write_text(text)
PY
git -C "$d" add -A
git -C "$d" commit -qm "fragment plus hand edit"
expect "a fragment does not license a hand edit" 1 "$d"

# 6. A malformed fragment is refused on its own, with no CHANGELOG edit
#    anywhere in the diff.
d="$work/case6"
new_repo "$d"
printf '{\n  "type": "nope",\n  "message": "x"\n}\n' \
  > "$d/docs/.changes/20260821-bad-type.json"
git -C "$d" add -A
git -C "$d" commit -qm "bad fragment"
expect "an unknown type fails" 1 "$d"

if [ "$failures" -ne 0 ]; then
  echo "changelog fragment guard: $failures case(s) failed" >&2
  exit 1
fi
echo "changelog fragment guard: all cases pass"

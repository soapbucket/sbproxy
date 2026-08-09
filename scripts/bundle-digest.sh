#!/usr/bin/env sh
#
# scripts/bundle-digest.sh
#
# Print the `digest_scope: bundle_v1` SHA-256 for one extension bundle
# directory. That digest covers `bundle.yaml` plus every other file the
# bundle ships, so it is not something `shasum -a 256 entry.js` can produce.
#
# The format is a text index, deliberately, so this script can exist:
#
#   sbproxy-bundle-digest/v1
#   <64 hex of file content>  <bundle-relative path>
#   ...
#
# sorted by path with LC_ALL=C, joined with `/`, one line per regular file,
# and the whole thing hashed once. `bundle.yaml` contributes the hash of its
# own bytes with its single top-level `sha256:` line deleted, because a digest
# cannot cover the field that carries it.
#
# This is a convenience for bundle authors, not part of the trusted path.
# sbproxy recomputes the digest itself on every candidate load and refuses the
# bundle on any mismatch.
#
# Usage:
#   scripts/bundle-digest.sh <bundle-directory>
#
# Then paste the value into that bundle's manifest:
#   sha256: <value>
#   digest_scope: bundle_v1
#
# Exit codes:
#   0  digest printed
#   1  the bundle cannot be digested (symlink, unterminated or ambiguous manifest)
#   2  invalid usage, or no SHA-256 tool on PATH

set -eu

case "${1:-}" in
  -h|--help)
    sed -n '2,33p' "$0"
    exit 0
    ;;
  "")
    echo "usage: scripts/bundle-digest.sh <bundle-directory>" >&2
    exit 2
    ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  sha256_stdin() { sha256sum | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_stdin() { shasum -a 256 | cut -d ' ' -f 1; }
else
  echo "bundle-digest.sh: needs sha256sum or shasum on PATH" >&2
  exit 2
fi

bundle=$1
if [ ! -d "$bundle" ]; then
  echo "bundle-digest.sh: not a directory: $bundle" >&2
  exit 2
fi
cd "$bundle"

if [ ! -f bundle.yaml ]; then
  echo "bundle-digest.sh: no bundle.yaml in $bundle" >&2
  exit 2
fi

# A symlink names bytes that live outside the digest and may live outside the
# bundle directory. sbproxy refuses one rather than following it, so refuse
# here too instead of printing a digest the loader will never accept.
if [ -n "$(find . -type l)" ]; then
  echo "bundle-digest.sh: refusing a bundle that contains a symlink" >&2
  exit 1
fi

if [ "$(tail -c 1 bundle.yaml | wc -l | tr -d ' ')" != "1" ]; then
  echo "bundle-digest.sh: bundle.yaml must end with a newline" >&2
  exit 1
fi

if [ "$(grep -c '^sha256:' bundle.yaml || true)" != "1" ]; then
  echo "bundle-digest.sh: bundle.yaml needs exactly one unquoted top-level sha256: line" >&2
  exit 1
fi

{
  printf 'sbproxy-bundle-digest/v1\n'
  find . -type f -print | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r path; do
    if [ "$path" = "bundle.yaml" ]; then
      content_digest=$(grep -v '^sha256:' bundle.yaml | sha256_stdin)
    else
      content_digest=$(sha256_stdin < "$path")
    fi
    printf '%s  %s\n' "$content_digest" "$path"
  done
} | sha256_stdin

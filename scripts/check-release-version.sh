#!/usr/bin/env bash
# Reject missing or stale build metadata before packaging or certification.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: check-release-version.sh BINARY FULL_GIT_SHA [VERSION]" >&2
  exit 2
fi
release_binary="$1"
expected_revision="$2"
expected_version="${3:-}"
if [[ ! "$expected_revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected revision must be a full lowercase Git SHA" >&2
  exit 1
fi
if ! version_line="$("$release_binary" --version)"; then
  echo "release binary failed to report its version" >&2
  exit 1
fi
printf '%s\n' "$version_line"
version_pattern='^sbproxy ([^[:space:]]+) \(rev ([0-9a-f]{7,40}), built ([0-9]{4}-[0-9]{2}-[0-9]{2})\)$'
if [[ ! "$version_line" =~ $version_pattern ]]; then
  echo "release binary has missing or malformed build metadata" >&2
  exit 1
fi
actual_version="${BASH_REMATCH[1]}"
actual_revision="${BASH_REMATCH[2]}"
if [[ "$expected_revision" != "$actual_revision"* ]]; then
  echo "release binary revision does not match the checked-out commit" >&2
  exit 1
fi
if [ -n "$expected_version" ] && [ "$actual_version" != "$expected_version" ]; then
  echo "release binary version does not match the release tag" >&2
  exit 1
fi

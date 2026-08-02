#!/usr/bin/env bash
# Show what a Listing plan reports when a manifest is wrong.
#
# The broken manifest cannot live in this example's own `listings/`
# directory: the repository sweeps every shipped `listings/` directory
# and requires it to validate clean, so a deliberately broken file there
# would fail the test suite rather than teach anybody anything. It lives
# in `invalid/` instead, and this script assembles a throwaway Repo from
# a copy of sb.yml plus that manifest.
#
# Usage:
#   bash examples/listing-primitive/bin/plan-error.sh

set -euo pipefail

example="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT

cp "$example/sb.yml" "$repo/sb.yml"
mkdir -p "$repo/listings"
cp "$example/invalid/orphan-listing.yaml" "$repo/listings/"

# `plan` exits 3 on any error finding, which is the point of the run.
sbproxy plan -f "$repo/sb.yml" 2>&1 || true

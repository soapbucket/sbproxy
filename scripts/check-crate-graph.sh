#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Soap Bucket LLC
#
# check-crate-graph.sh
#
# Enforce the hot-path / async-path layering pinned by
# `docs/adr-billing-hot-path-vs-async.md` (Rule 1): no OSS workspace
# crate (`sbproxy-rust/crates/*`) may depend on any
# `sbproxy-enterprise-*` crate. The proxy speaks only to
# `LedgerClient`; rail-specific code (Stripe, MPP, x402, Lightning)
# lives behind `BillingRail` and is consumed only by async workers in
# the enterprise tree.
#
# How it works:
#
#   1. Run `cargo metadata --format-version 1 --no-deps` to enumerate
#      the OSS workspace members. `--no-deps` keeps the output tight.
#   2. Run `cargo metadata --format-version 1` (with deps) and walk
#      every workspace member's `dependencies[].name`. Any name
#      starting with `sbproxy-enterprise` is a layering break.
#   3. Exit non-zero on the first violation; print a clear diagnostic.
#
# Runs from the repo root (`sbproxy-rust/`). Hooked into
# `.github/workflows/ci.yml` and `.github/workflows/wave1-gates.yml`
# so a regression breaks the PR.

set -euo pipefail

# --- Locate the workspace ---
#
# The script lives at `sbproxy-rust/scripts/check-crate-graph.sh`. We
# resolve the repo root from the script path so the check runs the
# same way under CI (`cwd = repo root`) as locally (`cwd = anywhere`).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# --- Sanity check: cargo + jq present ---
#
# `jq` is the cleanest way to walk `cargo metadata`'s JSON. CI
# already installs it as part of the standard runner image; locally
# the developer either has it or the script fails fast with a clear
# message.
if ! command -v cargo >/dev/null 2>&1; then
    echo "check-crate-graph: cargo not found in PATH" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "check-crate-graph: jq not found in PATH" >&2
    echo "  install with: brew install jq  (or apt-get install jq)" >&2
    exit 2
fi

# --- Pull the metadata ---
#
# `--no-deps` only emits workspace members. We still need the
# dependency edges, so we run a second pass without `--no-deps`.
WORKSPACE_JSON="$(cargo metadata --format-version 1 --no-deps 2>/dev/null)"
DEPS_JSON="$(cargo metadata --format-version 1 2>/dev/null)"

# --- Find OSS workspace members ---
#
# Workspace members appear in `packages[]` with `id` matching the
# `workspace_members[]` list. Filter to that intersection so we only
# inspect the OSS crates this script is meant to gate.
WORKSPACE_MEMBERS="$(echo "${WORKSPACE_JSON}" \
    | jq -r '.workspace_members[]')"

# --- Walk dependencies for each member ---
#
# For each workspace member, list its `dependencies[].name`. A name
# starting with `sbproxy-enterprise` is the layering violation.
VIOLATIONS=0
while IFS= read -r member_id; do
    # Each `member_id` looks like `sbproxy-modules 1.0.0 (path+file://...)`.
    # Pull the package name (first whitespace-separated field).
    member_name="${member_id%% *}"

    # Filter dependencies, excluding dev-dependencies which are
    # allowed to reach for fixtures (we still want to flag direct prod
    # deps).
    bad_deps="$(echo "${DEPS_JSON}" \
        | jq -r --arg id "${member_id}" '
            .packages[]
            | select(.id == $id)
            | .dependencies[]
            | select(.kind == null or .kind == "normal")
            | select(.name | startswith("sbproxy-enterprise"))
            | .name
        ' || true)"

    if [[ -n "${bad_deps}" ]]; then
        if [[ "${VIOLATIONS}" -eq 0 ]]; then
            echo "check-crate-graph: hot-path / async-path layering violation" >&2
            echo "  per docs/adr-billing-hot-path-vs-async.md Rule 1" >&2
            echo "" >&2
        fi
        while IFS= read -r dep; do
            echo "  ${member_name} -> ${dep}" >&2
            VIOLATIONS=$((VIOLATIONS + 1))
        done <<< "${bad_deps}"
    fi
done <<< "${WORKSPACE_MEMBERS}"

if [[ "${VIOLATIONS}" -gt 0 ]]; then
    echo "" >&2
    echo "Found ${VIOLATIONS} OSS -> enterprise edge(s)." >&2
    echo "OSS crates must call enterprise functionality only via the" >&2
    echo "LedgerClient trait in sbproxy-plugin." >&2
    exit 1
fi

echo "check-crate-graph: ok (no OSS -> enterprise edges)"
exit 0

#!/usr/bin/env bash
# Shared helper for the generated-artifact freshness checks.
#
# Those checks each run a small generator binary and diff its output against a
# committed file. A standalone check can invoke one with `cargo run -p
# <crate> --bin <name>` because no workspace build is available to reuse.
#
# After a workspace build, re-entering Cargo is wasteful. Under resolver = "2"
# Cargo computes the feature union from the selected packages, so a narrow
# `-p sbproxy-config` invocation can rebuild the dependency graph to run a
# binary already sitting in target/debug. Four checks doing this cost about
# two minutes per run.
#
# When SBPROXY_PREBUILT_BINS=1 is set, run the already-built binary instead.
# The caller is responsible for having built it with a workspace-wide
# selection first. If the binary is missing we fall back to `cargo run` rather
# than failing, so a partial build still produces a real answer.

# run_workspace_bin <bin-name> <cargo-run-args...>
#
#   run_workspace_bin generate-schema -p sbproxy-config --bin generate-schema
run_workspace_bin() {
    local bin_name="$1"
    shift

    local target_dir="${CARGO_TARGET_DIR:-target}"
    local prebuilt="${target_dir}/debug/${bin_name}"

    if [ "${SBPROXY_PREBUILT_BINS:-0}" = "1" ] && [ -x "${prebuilt}" ]; then
        "${prebuilt}"
        return
    fi

    cargo run --quiet "$@"
}

# Run generated-artifact checks against binaries from the workspace build.
# Each script still owns its Cargo invocation, so a missing binary falls back
# through run_workspace_bin and any Cargo failure stops the gate.
run_generated_artifact_checks() {
    local workspace_root="$1"
    shift

    local check
    for check in "$@"; do
        SBPROXY_PREBUILT_BINS=1 bash "${workspace_root}/scripts/${check}" || return $?
    done
}

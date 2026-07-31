#!/usr/bin/env bash
# Shared helper for the generated-artifact freshness checks.
#
# Those checks each run a small generator binary and diff its output against a
# committed file. The obvious way to invoke one is `cargo run -p <crate>
# --bin <name>`, and locally that is the right call.
#
# In CI it is not. Under resolver = "2" cargo computes the feature union from
# the set of *selected* packages, so `-p sbproxy-config` resolves a narrower
# feature set than the `--workspace` build that just ran, every fingerprint
# differs, and cargo rebuilds the dependency graph to run a binary that is
# already sitting in target/debug. Four checks doing this cost about two
# minutes per run.
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

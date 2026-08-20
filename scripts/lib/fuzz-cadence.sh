#!/usr/bin/env bash
# Cadence, prerequisites, and paths for the local fuzz phase in check.sh.
#
# The fuzz harnesses used to be a CI lane, `.github/workflows/wave4-fuzz.yml`.
# Its job condition was `workflow_dispatch || contains(labels, 'run-fuzz')`,
# and the `run-fuzz` label was never created in the repository, so the pull
# request arm was always false and the harnesses only ever ran when somebody
# fired the workflow by hand. Nobody did. A lane that reads as coverage on
# the workflow list and runs zero times is worse than no lane, so the CI file
# is gone and the harnesses moved here, where they run on a clock.
#
# The decisions this file owns:
#
#   * When is a run due?  A stamp file records the last pass. Older than the
#     cadence, or absent, means due.
#   * Can a run happen?   cargo-fuzz is nightly-only and neither nightly nor
#     cargo-fuzz ships with a plain `cargo`. A missing prerequisite prints
#     the install commands and skips; it never fails the gate, and it never
#     reads as a pass.
#   * Where does the state live?  Outside the repository, per machine.
#
# That last one is the load-bearing choice. This checkout carries about
# thirty worktrees at a time. A stamp under `target/` or anywhere else
# inside the tree is per worktree, so every new branch directory would look
# like a machine that has never fuzzed and would trigger a cold multi-gigabyte
# build of the full proxy graph on its first gate. Whoever hit that twice
# would turn the phase off, which is the dead-lane failure the CI label
# already demonstrated. The cadence is a property of the developer's machine
# and the calendar, not of a branch, so the stamp and the fuzz target
# directory both live under the user's state and cache directories and are
# shared by every worktree. Nothing this file writes can ever be committed.
#
# Everything below is overridable so the self-test in
# scripts/tests/fuzz_cadence_test.sh can drive it against a sandbox.

# Cadence in days. Seven, for three reasons: the harnesses cover parsers and
# script engines that change on the order of weeks rather than hours; the
# repository already schedules its heavy sweeps weekly (the full e2e suite
# runs 09:30 UTC Mondays); and one gate run in seven paying a few minutes is
# a cost a developer absorbs, where a few minutes on every run is a cost
# somebody removes.
SBPROXY_FUZZ_DEFAULT_MAX_AGE_DAYS=7

# libfuzzer seconds per target. Ten targets, so the campaign itself is about
# two and a half minutes; see the phase comment in check.sh for the full
# wall-clock picture including the build. Lower than the 30 and 60 second
# budgets the CI matrix carried because that matrix fanned out across ten
# parallel runners and this runs serially on one laptop, and because a weekly
# 15 seconds per target is strictly more fuzzing than the CI lane ever
# delivered on a pull request, which was none.
SBPROXY_FUZZ_DEFAULT_SECONDS=15

# Per-machine state directory. Holds the stamp only.
fuzz_state_dir() {
  if [ -n "${SBPROXY_FUZZ_STATE_DIR:-}" ]; then
    printf '%s\n' "${SBPROXY_FUZZ_STATE_DIR}"
  else
    printf '%s/sbproxy\n' "${XDG_STATE_HOME:-$HOME/.local/state}"
  fi
}

# The stamp. Line 1 is the epoch second of the last pass, which is what the
# cadence reads; line 2 is a human-readable timestamp so the file explains
# itself when somebody opens it. Epoch seconds in the content rather than the
# file's mtime because `stat` takes different flags on macOS and Linux and
# this gate runs on both.
fuzz_stamp_path() {
  printf '%s/fuzz-last-pass\n' "$(fuzz_state_dir)"
}

# Per-machine cargo target directory for the fuzz crate.
#
# The fuzz crate path-depends on the proxy, so it builds pingora, tract-onnx
# and tokenizers: several gigabytes. It must not land in the workspace
# `target/`, which every other lane in the gate shares, because cargo-fuzz
# builds with sanitizer flags and a nightly compiler and would invalidate the
# stable workspace fingerprints on every run. cargo-fuzz's own default,
# `fuzz/target/`, is inside the tree and therefore per worktree, which is the
# same multiplication problem as the stamp. One shared directory per machine
# instead: one copy of the several gigabytes, reused by every branch.
#
# Reclaim it with `rm -rf "$(fuzz_target_dir)"`; nothing else reads it, and
# neither `cargo clean` nor scripts/cleanup-build-artifacts.sh touches it.
fuzz_target_dir() {
  if [ -n "${SBPROXY_FUZZ_TARGET_DIR:-}" ]; then
    printf '%s\n' "${SBPROXY_FUZZ_TARGET_DIR}"
  else
    printf '%s/sbproxy/fuzz-target\n' "${XDG_CACHE_HOME:-$HOME/.cache}"
  fi
}

# Per-machine corpus root, one directory per target underneath.
#
# Not `fuzz/corpus/`, which is where cargo-fuzz writes by default, because
# libfuzzer treats its first corpus argument as an output directory and grows
# it with every interesting input it finds. Only `cel_script` has committed
# seeds, so a default run would create nine untracked directories inside the
# repository and grow the tenth, and the gate's own working-tree guard would
# then fail the run it just finished. The committed seeds are still used:
# they are passed as a second, read-only corpus argument by check.sh.
fuzz_corpus_dir() {
  if [ -n "${SBPROXY_FUZZ_CORPUS_DIR:-}" ]; then
    printf '%s\n' "${SBPROXY_FUZZ_CORPUS_DIR}"
  else
    printf '%s/sbproxy/fuzz-corpus\n' "${XDG_CACHE_HOME:-$HOME/.cache}"
  fi
}

fuzz_max_age_days() {
  printf '%s\n' "${SBPROXY_FUZZ_MAX_AGE_DAYS:-$SBPROXY_FUZZ_DEFAULT_MAX_AGE_DAYS}"
}

fuzz_seconds_per_target() {
  printf '%s\n' "${SBPROXY_FUZZ_SECONDS:-$SBPROXY_FUZZ_DEFAULT_SECONDS}"
}

# Whole days since the last recorded pass, or `never`.
#
# `never` is also the answer for a stamp that is missing, empty, non-numeric,
# or dated in the future. Every one of those is a stamp this file cannot
# trust, and the safe direction for an untrusted stamp is to run the phase
# rather than to report a pass that may never have happened.
fuzz_stamp_age_days() {
  local stamp recorded now
  stamp="$(fuzz_stamp_path)"
  if [ ! -f "$stamp" ]; then
    printf 'never\n'
    return 0
  fi
  recorded="$(head -n 1 "$stamp" 2>/dev/null || true)"
  case "$recorded" in
    '' | *[!0-9]*)
      printf 'never\n'
      return 0
      ;;
  esac
  now="$(date +%s)"
  if [ "$recorded" -gt "$now" ]; then
    printf 'never\n'
    return 0
  fi
  printf '%s\n' "$(((now - recorded) / 86400))"
}

# The first missing prerequisite, as one of `rustup`, `nightly`, or
# `cargo-fuzz`. Prints nothing when the toolchain is complete.
#
# Ordered the way the install is ordered, so the answer is always the next
# thing to do rather than the last thing that failed. rustup is probed first
# because without it `cargo +nightly` reports `no such command: +nightly`,
# which names the wrong problem.
fuzz_missing_prereq() {
  if ! command -v rustup >/dev/null 2>&1; then
    printf 'rustup\n'
    return 0
  fi
  if ! cargo +nightly --version >/dev/null 2>&1; then
    printf 'nightly\n'
    return 0
  fi
  if ! command -v cargo-fuzz >/dev/null 2>&1; then
    printf 'cargo-fuzz\n'
    return 0
  fi
  return 0
}

# The install block for a missing prerequisite. Multi-line and imperative:
# this is the text that has to stop somebody from reading a skip as a pass,
# so it names the exact commands rather than the missing tool.
fuzz_prereq_hint() {
  local missing="$1"
  printf 'The fuzz phase is DUE and did NOT run: %s is missing.\n\n' "$missing"
  printf 'cargo-fuzz is nightly-only and neither nightly nor cargo-fuzz ships\n'
  printf 'with a plain cargo install. Run these three, in order:\n\n'
  printf '  curl --proto '"'"'=https'"'"' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n'
  printf '  rustup toolchain install nightly\n'
  printf '  cargo install cargo-fuzz\n\n'
  printf 'Two things bite on the way through. Homebrew rust and rustup both\n'
  printf 'provide a cargo, so put rustup ahead of Homebrew on PATH or the\n'
  printf 'stable Homebrew cargo keeps answering and +nightly keeps failing.\n'
  printf 'And cargo install lands cargo-fuzz in ~/.cargo/bin, which has to be\n'
  printf 'on PATH for this phase to find it:\n\n'
  # shellcheck disable=SC2016  # the line is printed for the reader to run
  printf '  export PATH="$HOME/.cargo/bin:$PATH"\n\n'
  printf 'To silence this until you are ready, set SBPROXY_CHECK_FUZZ=0. That\n'
  printf 'is a decision to skip the harnesses, not a way to make them pass.\n'
}

# The phase decision, as `<verdict>|<detail>` on one line.
#
#   run|<why>            run the harnesses now
#   skip-off|<why>       SBPROXY_CHECK_FUZZ=0 turned the phase off
#   skip-fresh|<why>     inside the cadence window; nothing to do, and not
#                        worth a SKIPPED entry, because this is the normal
#                        state on six runs out of seven
#   skip-missing|<tool>  due, but a prerequisite is missing
#
# The prerequisite probe runs last on purpose. A machine without nightly
# should be told about it when a run was actually due, not on every gate run
# forever, and once it is due the message repeats on every run until the
# toolchain is installed or the phase is explicitly turned off, because the
# stamp only advances on a pass.
fuzz_phase_plan() {
  local flag max age due missing
  flag="${SBPROXY_CHECK_FUZZ:-}"

  if [ "$flag" = "0" ]; then
    printf 'skip-off|SBPROXY_CHECK_FUZZ=0\n'
    return 0
  fi

  max="$(fuzz_max_age_days)"
  age="$(fuzz_stamp_age_days)"

  if [ "$flag" = "1" ]; then
    due='forced'
  elif [ "$age" = 'never' ]; then
    due='never'
  elif [ "$age" -ge "$max" ]; then
    due='elapsed'
  else
    due=''
  fi

  if [ -z "$due" ]; then
    printf 'skip-fresh|last pass %s day(s) ago, cadence is %s day(s); next run due in %s. SBPROXY_CHECK_FUZZ=1 forces one now\n' \
      "$age" "$max" "$((max - age))"
    return 0
  fi

  missing="$(fuzz_missing_prereq)"
  if [ -n "$missing" ]; then
    printf 'skip-missing|%s\n' "$missing"
    return 0
  fi

  case "$due" in
    forced) printf 'run|SBPROXY_CHECK_FUZZ=1 forced a run\n' ;;
    never) printf 'run|no recorded pass on this machine\n' ;;
    elapsed) printf 'run|last pass %s day(s) ago, cadence is %s day(s)\n' "$age" "$max" ;;
  esac
}

# Record a pass. Called only after every target has come back clean, so the
# cadence measures successful passes and a crash re-runs on the next gate.
fuzz_record_pass() {
  local dir stamp
  dir="$(fuzz_state_dir)"
  mkdir -p "$dir"
  stamp="$(fuzz_stamp_path)"
  {
    date +%s
    printf '# last clean scripts/check.sh fuzz phase: %s\n' \
      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } >"$stamp"
}

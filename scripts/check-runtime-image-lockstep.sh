#!/usr/bin/env bash
# Fleet runtime images stay in lockstep on /var/lib/sbproxy and the
# distroless Debian generation (WOR-2705, WOR-2713).
#
# # Why this exists
#
# WOR-2087 taught Dockerfile.ci and the inline release Dockerfile to
# COPY an empty /var/lib/sbproxy owned by uid 65532, because the
# documented defaults for the keystore and usage rollups live there and
# a nonroot distroless user cannot create the directory. Dockerfile.gateway,
# Dockerfile.worker, and Dockerfile.cloudbuild never received that COPY.
# A later fleet-image split forked those files from each other and the
# gap survived.
#
# WOR-2713 is the same shape on the runtime base. Fetched mistral.rs
# prebuilts need GLIBC_2.38 or newer. cc-debian12 ships 2.36, so those
# engines cannot start. cc-debian13 ships 2.41. The sbproxy binary itself
# must still require <= 2.36 (MAX_ALLOWED in release.yml) so Linux
# tarballs run on Debian 12. Older glibc binaries run on newer glibc,
# so debian13 is a strict superset for the container runtime.
#
# # What this checks
#
# Each file below must contain a runtime-stage COPY whose destination is
# /var/lib/sbproxy:
#
#   Dockerfile.ci
#   Dockerfile.gateway
#   Dockerfile.worker
#   Dockerfile.cloudbuild
#   .github/workflows/release.yml   (the inline Dockerfile heredoc)
#
# Each distroless runtime FROM must not still name cc-debian12:
#
#   Dockerfile.ci
#   Dockerfile.gateway
#   Dockerfile.cloudbuild
#   .github/workflows/release.yml
#
# Dockerfile.worker is CUDA / Ubuntu, not distroless. It still needs the
# /var/lib/sbproxy COPY. It is not required to name cc-debian13.
#
# Builder images stay on rust:bookworm. This script does not look at them.
#
# # Usage
#
#   scripts/check-runtime-image-lockstep.sh              # self-test, then the tree
#   scripts/check-runtime-image-lockstep.sh --self-test  # fixtures only
#
# The self-test fixtures are the gap this check exists to catch: a
# gateway/worker/cloudbuild tree without the COPY, and a distroless FROM
# still on cc-debian12. If those fixtures start passing, the detector
# has gone quiet.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Runtime images that must ship /var/lib/sbproxy. release.yml's heredoc
# is the published soapbucket/sbproxy image; the four Dockerfiles are
# the CI, Cloud Build, and fleet-split variants.
VARLIB_FILES=(
  Dockerfile.ci
  Dockerfile.gateway
  Dockerfile.worker
  Dockerfile.cloudbuild
  .github/workflows/release.yml
)

# Distroless runtimes that must not still pin cc-debian12.
# Dockerfile.worker is excluded on purpose: nvidia/cuda Ubuntu, not
# distroless. mistral.rs-on-distroless is the ticket.
DISTROLESS_FILES=(
  Dockerfile.ci
  Dockerfile.gateway
  Dockerfile.cloudbuild
  .github/workflows/release.yml
)

# A COPY instruction whose last path is /var/lib/sbproxy. Comments are
# ignored. Matches both `COPY --from=builder --chown=65532:65532
# /var/lib/sbproxy /var/lib/sbproxy` and the release.yml form
# `COPY --chown=65532:65532 var/lib/sbproxy /var/lib/sbproxy`.
VARLIB_COPY_RE='^[[:space:]]*COPY[[:space:]].+[[:space:]]/var/lib/sbproxy[[:space:]]*$'

# A FROM line that still names the debian12 distroless tag. Comments
# that mention the old tag do not match.
DEBIAN12_FROM_RE='^[[:space:]]*FROM[[:space:]].*cc-debian12'

has_varlib_copy() {
  grep -E "$VARLIB_COPY_RE" "$1" >/dev/null
}

has_debian12_from() {
  grep -E "$DEBIAN12_FROM_RE" "$1" >/dev/null
}

scan_tree() {
  local root="$1"
  local rel file failed=0

  for rel in "${VARLIB_FILES[@]}"; do
    file="$root/$rel"
    if [ ! -f "$file" ]; then
      printf '%s: missing; fleet images cannot stay in lockstep without it\n' "$rel" >&2
      failed=1
      continue
    fi
    if ! has_varlib_copy "$file"; then
      printf '%s: runtime stage is missing a COPY of /var/lib/sbproxy (WOR-2705)\n' "$rel" >&2
      failed=1
    fi
  done

  for rel in "${DISTROLESS_FILES[@]}"; do
    file="$root/$rel"
    if [ ! -f "$file" ]; then
      printf '%s: missing; cannot confirm the distroless runtime base\n' "$rel" >&2
      failed=1
      continue
    fi
    if has_debian12_from "$file"; then
      printf '%s: distroless runtime FROM still names cc-debian12; use cc-debian13 (WOR-2713)\n' "$rel" >&2
      failed=1
    fi
  done

  if [ "$failed" -ne 0 ]; then
    return 1
  fi
  printf 'runtime image lockstep: /var/lib/sbproxy COPY present, no cc-debian12 distroless FROM\n'
  return 0
}

self_test() {
  local scratch status failures=0
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-runtime-image-lockstep.XXXXXX")"
  trap 'rm -rf "$scratch"' RETURN

  expect() {
    local label="$1" want="$2"
    shift 2
    set +e
    "$@" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -ne "$want" ]; then
      echo "self-test: $label expected exit $want, got $status" >&2
      failures=1
    fi
  }

  # The gap on main when WOR-2705 and WOR-2713 were filed: ci and the
  # release heredoc already COPY /var/lib/sbproxy, the fleet/cloudbuild
  # files do not, and every distroless FROM is still cc-debian12.
  mkdir -p "$scratch/old/.github/workflows"
  cat >"$scratch/old/Dockerfile.ci" <<'EOF'
FROM rust:1.95-bookworm AS builder
RUN mkdir -p /var/lib/sbproxy
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=builder --chown=65532:65532 /var/lib/sbproxy /var/lib/sbproxy
EOF
  cat >"$scratch/old/Dockerfile.gateway" <<'EOF'
FROM rust:1.95-bookworm AS builder
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=builder /usr/local/bin/sbproxy /usr/local/bin/sbproxy
EOF
  cat >"$scratch/old/Dockerfile.worker" <<'EOF'
FROM rust:1.95-bookworm AS builder
FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04 AS runtime
COPY --from=builder /usr/local/bin/sbproxy /usr/local/bin/sbproxy
EOF
  cat >"$scratch/old/Dockerfile.cloudbuild" <<'EOF'
FROM rust:1.95-bookworm AS builder
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=builder /usr/local/bin/sbproxy /usr/local/bin/sbproxy
EOF
  cat >"$scratch/old/.github/workflows/release.yml" <<'EOF'
          FROM gcr.io/distroless/cc-debian12:nonroot
          COPY --chown=65532:65532 var/lib/sbproxy /var/lib/sbproxy
EOF
  expect "the pre-fix tree is refused" 1 scan_tree "$scratch/old"

  # A comment that names the old tag must not trip the FROM matcher.
  mkdir -p "$scratch/comment/.github/workflows"
  cat >"$scratch/comment/Dockerfile.ci" <<'EOF'
# Keep in sync on distroless/cc-debian12 historically; runtime is 13 now.
FROM rust:1.95-bookworm AS builder
RUN mkdir -p /var/lib/sbproxy
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
COPY --from=builder --chown=65532:65532 /var/lib/sbproxy /var/lib/sbproxy
EOF
  cp "$scratch/comment/Dockerfile.ci" "$scratch/comment/Dockerfile.gateway"
  cat >"$scratch/comment/Dockerfile.worker" <<'EOF'
FROM rust:1.95-bookworm AS builder
RUN mkdir -p /var/lib/sbproxy
FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04 AS runtime
COPY --from=builder --chown=65532:65532 /var/lib/sbproxy /var/lib/sbproxy
EOF
  cp "$scratch/comment/Dockerfile.ci" "$scratch/comment/Dockerfile.cloudbuild"
  cat >"$scratch/comment/.github/workflows/release.yml" <<'EOF'
          # historically cc-debian12
          FROM gcr.io/distroless/cc-debian13:nonroot
          COPY --chown=65532:65532 var/lib/sbproxy /var/lib/sbproxy
EOF
  expect "a comment naming cc-debian12 does not fail" 0 scan_tree "$scratch/comment"

  # Worker may keep the CUDA base; it still needs the COPY.
  mkdir -p "$scratch/worker-gap/.github/workflows"
  cat >"$scratch/worker-gap/Dockerfile.ci" <<'EOF'
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
COPY --from=builder --chown=65532:65532 /var/lib/sbproxy /var/lib/sbproxy
EOF
  cp "$scratch/worker-gap/Dockerfile.ci" "$scratch/worker-gap/Dockerfile.gateway"
  cp "$scratch/worker-gap/Dockerfile.ci" "$scratch/worker-gap/Dockerfile.cloudbuild"
  cat >"$scratch/worker-gap/Dockerfile.worker" <<'EOF'
FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04 AS runtime
COPY --from=builder /usr/local/bin/sbproxy /usr/local/bin/sbproxy
EOF
  cat >"$scratch/worker-gap/.github/workflows/release.yml" <<'EOF'
          FROM gcr.io/distroless/cc-debian13:nonroot
          COPY --chown=65532:65532 var/lib/sbproxy /var/lib/sbproxy
EOF
  expect "worker without the COPY is refused" 1 scan_tree "$scratch/worker-gap"

  # The tree this change lands: COPY everywhere, debian13 on distroless,
  # worker still on CUDA.
  mkdir -p "$scratch/good/.github/workflows"
  cat >"$scratch/good/Dockerfile.ci" <<'EOF'
FROM rust:1.95-bookworm AS builder
RUN mkdir -p /var/lib/sbproxy
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
COPY --from=builder --chown=65532:65532 /var/lib/sbproxy /var/lib/sbproxy
EOF
  cp "$scratch/good/Dockerfile.ci" "$scratch/good/Dockerfile.gateway"
  cat >"$scratch/good/Dockerfile.worker" <<'EOF'
FROM rust:1.95-bookworm AS builder
RUN mkdir -p /var/lib/sbproxy
FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04 AS runtime
COPY --from=builder --chown=65532:65532 /var/lib/sbproxy /var/lib/sbproxy
EOF
  cp "$scratch/good/Dockerfile.ci" "$scratch/good/Dockerfile.cloudbuild"
  cat >"$scratch/good/.github/workflows/release.yml" <<'EOF'
          FROM gcr.io/distroless/cc-debian13:nonroot
          COPY --chown=65532:65532 var/lib/sbproxy /var/lib/sbproxy
EOF
  expect "the fixed tree passes" 0 scan_tree "$scratch/good"

  if [ "$failures" -ne 0 ]; then
    echo "self-test failed: the detector is narrower than the gap" >&2
    return 1
  fi
  echo "self-test passed: pre-fix tree refused, comment ignored, worker COPY required, fixed tree passes"
  return 0
}

case "${1:-}" in
  --self-test) self_test ;;
  "") self_test && scan_tree "$ROOT_DIR" ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac

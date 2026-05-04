#!/usr/bin/env bash
# Build a darwin release tarball on this Mac and upload it to a GitHub
# release. Use when the CI matrix darwin slot is wedged and you need
# to ship without waiting for the runner pool.
#
# Usage:
#   scripts/release-darwin-local.sh <tag> [--target <triple>]
#
# Examples:
#   # Apple Silicon Mac, build for the host arch:
#   scripts/release-darwin-local.sh v1.0.0
#
#   # Apple Silicon Mac, cross-compile for Intel Mac (requires the
#   # x86_64-apple-darwin std lib; install via rustup):
#   scripts/release-darwin-local.sh v1.0.0 --target x86_64-apple-darwin
#
# Prerequisites:
#   * Rust toolchain with the chosen target installed.
#     Brew rust ships only the host target. For x86_64-apple-darwin
#     from Apple Silicon, install rustup:
#       curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#       rustup target add x86_64-apple-darwin
#   * `gh` CLI authenticated with write scope on the repo.
#   * Working tree at the tag you are uploading to (so the binary's
#     embedded git SHA matches the tag).

set -euo pipefail

if [ "$#" -lt 1 ]; then
  sed -n '2,20p' "$0" >&2
  exit 2
fi

TAG="$1"
shift

TARGET=""
case "$(uname -m)" in
  arm64)  HOST_TARGET="aarch64-apple-darwin" ;;
  x86_64) HOST_TARGET="x86_64-apple-darwin" ;;
  *) echo "unsupported host arch: $(uname -m)" >&2; exit 2 ;;
esac
TARGET="${HOST_TARGET}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

case "${TARGET}" in
  aarch64-apple-darwin) PLATFORM="darwin_arm64" ;;
  x86_64-apple-darwin)  PLATFORM="darwin_amd64" ;;
  *) echo "unsupported target: ${TARGET}" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo ">> building ${TARGET} for tag ${TAG}"
cargo build --release --locked --target "${TARGET}" --bin sbproxy

STAGE_DIR="$(mktemp -d)/sbproxy-${TAG}-${PLATFORM}"
mkdir -p "${STAGE_DIR}"
cp "target/${TARGET}/release/sbproxy" "${STAGE_DIR}/sbproxy"
for f in LICENSE NOTICE README.md SECURITY.md SUPPLY-CHAIN.md; do
  [ -f "$f" ] && cp "$f" "${STAGE_DIR}/" || true
done

DIST_DIR="${REPO_ROOT}/dist"
mkdir -p "${DIST_DIR}"
TAR="${DIST_DIR}/sbproxy_${PLATFORM}.tar.gz"
tar -czf "${TAR}" -C "${STAGE_DIR}" .
(cd "${DIST_DIR}" && shasum -a 256 "$(basename "${TAR}")" > "$(basename "${TAR}").sha256")

echo ">> built artifacts:"
ls -la "${DIST_DIR}/sbproxy_${PLATFORM}".*

if ! gh release view "${TAG}" >/dev/null 2>&1; then
  echo ">> release ${TAG} does not exist yet; not uploading."
  echo "   Run: gh release create ${TAG} --notes-file CHANGELOG.md --draft"
  echo "   Then: gh release upload ${TAG} ${TAR} ${TAR}.sha256"
  exit 0
fi

echo ">> uploading to release ${TAG}"
gh release upload "${TAG}" --clobber "${TAR}" "${TAR}.sha256"
echo ">> done"

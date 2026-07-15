#!/bin/sh
# Exercise the integrity checks in scripts/install.sh against a local fixture.
#
# WOR-1914: the installer used to download a binary and never verify it. These
# cases prove the two things that matter: a tampered download aborts and leaves
# nothing installed, and a clean download verifies and installs. Run directly:
#
#   sh scripts/tests/install_verify.sh
#
# It builds a fake release (a fake "binary" in a tarball, plus a .sha256) in a
# temp dir, points the installer at it with SBPROXY_BASE_URL, and asserts on the
# outcome. No network, no cargo, no real binary.

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL_SH="${REPO_ROOT}/scripts/install.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Resolve the asset name the installer will ask for on this host.
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
esac
ARCHIVE="sbproxy_${OS}_${ARCH}.tar.gz"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    fi
}

# --- Build a fake release under $WORK/release ---
RELEASE="${WORK}/release"
mkdir -p "$RELEASE"
printf '#!/bin/sh\necho "sbproxy fake 9.9.9"\n' > "${WORK}/sbproxy"
chmod +x "${WORK}/sbproxy"
tar czf "${RELEASE}/${ARCHIVE}" -C "$WORK" sbproxy
( cd "$RELEASE" && sha256_of "$ARCHIVE" | awk -v f="$ARCHIVE" '{print $1"  "f}' \
    > "${ARCHIVE}.sha256" )

PASS=0
FAIL=0
check() {
    _name="$1"; _ok="$2"
    if [ "$_ok" = "1" ]; then
        echo "  ok   - ${_name}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL - ${_name}"
        FAIL=$((FAIL + 1))
    fi
}

run_installer() {
    _dest="$1"
    SBPROXY_VERSION="v9.9.9" \
    SBPROXY_BASE_URL="file://${RELEASE}" \
    SBPROXY_INSTALL="$_dest" \
    SBPROXY_SKIP_COSIGN=1 \
    sh "$INSTALL_SH" >"${WORK}/out.log" 2>&1
}

# --- Case 1: happy path verifies and installs ---
DEST1="${WORK}/bin1"
if run_installer "$DEST1"; then rc=0; else rc=$?; fi
check "happy path exits 0" "$([ "$rc" = "0" ] && echo 1 || echo 0)"
check "happy path installs the binary" "$([ -x "${DEST1}/sbproxy" ] && echo 1 || echo 0)"
check "happy path reports the checksum verified" \
    "$(grep -q 'Checksum verified' "${WORK}/out.log" && echo 1 || echo 0)"

# --- Case 2: a flipped byte in the tarball aborts and installs nothing ---
# Corrupt the archive but leave the (now non-matching) .sha256 in place.
printf 'tampered' >> "${RELEASE}/${ARCHIVE}"
DEST2="${WORK}/bin2"
if run_installer "$DEST2"; then rc=0; else rc=$?; fi
check "tampered download exits non-zero" "$([ "$rc" != "0" ] && echo 1 || echo 0)"
check "tampered download installs nothing" \
    "$([ ! -e "${DEST2}/sbproxy" ] && echo 1 || echo 0)"
check "tampered download says checksum mismatch" \
    "$(grep -q 'checksum mismatch' "${WORK}/out.log" && echo 1 || echo 0)"

# --- Case 3: a missing .sha256 aborts (fail closed, do not skip) ---
RELEASE2="${WORK}/release_nohash"
mkdir -p "$RELEASE2"
tar czf "${RELEASE2}/${ARCHIVE}" -C "$WORK" sbproxy
DEST3="${WORK}/bin3"
if SBPROXY_VERSION="v9.9.9" SBPROXY_BASE_URL="file://${RELEASE2}" \
   SBPROXY_INSTALL="$DEST3" SBPROXY_SKIP_COSIGN=1 \
   sh "$INSTALL_SH" >"${WORK}/out3.log" 2>&1; then rc=0; else rc=$?; fi
check "missing checksum exits non-zero" "$([ "$rc" != "0" ] && echo 1 || echo 0)"
check "missing checksum installs nothing" \
    "$([ ! -e "${DEST3}/sbproxy" ] && echo 1 || echo 0)"

echo ""
echo "install_verify: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" = "0" ]

#!/usr/bin/env bash
# update-homebrew.sh
#
# Updates the Homebrew formula in the homebrew-sbproxy tap after a release.
# Downloads release artifacts, computes SHA256 hashes, updates the formula,
# commits, and pushes.
#
# Usage:
#   ./scripts/update-homebrew.sh              # Uses version from VERSION file
#   ./scripts/update-homebrew.sh 0.2.0        # Explicit version
#
# Prerequisites:
#   - The soapbucket/homebrew-sbproxy repo must be cloned next to this repo
#   - GitHub releases must exist at the specified version tag
#   - curl, shasum (or sha256sum)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOMEBREW_REPO="$(cd "$REPO_ROOT/../homebrew-sbproxy" 2>/dev/null && pwd)" || {
    echo "ERROR: homebrew-sbproxy repo not found at $REPO_ROOT/../homebrew-sbproxy"
    echo "Clone it: git clone git@github.com:soapbucket/homebrew-sbproxy.git"
    exit 1
}

FORMULA="$HOMEBREW_REPO/sbproxy.rb"

if [[ ! -f "$FORMULA" ]]; then
    echo "ERROR: Formula not found at $FORMULA"
    exit 1
fi

# Determine version
VERSION="${1:-$(cat "$REPO_ROOT/VERSION" 2>/dev/null | tr -d '[:space:]')}"
if [[ -z "$VERSION" ]]; then
    echo "ERROR: No version specified and VERSION file not found."
    echo "Usage: $0 <version>"
    exit 1
fi

echo "==> Updating Homebrew formula for sbproxy v${VERSION}"

# Portable SHA256
if command -v sha256sum &>/dev/null; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum &>/dev/null; then
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "ERROR: sha256sum or shasum required" >&2
    exit 1
fi

BASE_URL="https://github.com/soapbucket/sbproxy/releases/download/v${VERSION}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Download and hash each platform
declare -A HASHES
PLATFORMS=("darwin_arm64" "darwin_amd64" "linux_arm64" "linux_amd64")

for platform in "${PLATFORMS[@]}"; do
    archive="sbproxy_${platform}.tar.gz"
    url="${BASE_URL}/${archive}"
    dest="${TMPDIR}/${archive}"

    echo "  Downloading ${archive}..."
    if curl -fsSL "$url" -o "$dest" 2>/dev/null; then
        HASHES[$platform]=$(sha256 "$dest")
        echo "    sha256: ${HASHES[$platform]}"
    else
        echo "    WARN: $archive not found at $url (skipping)"
        HASHES[$platform]="PLACEHOLDER_${platform^^}"
    fi
done

# Update the formula
echo ""
echo "==> Updating $FORMULA"

sed -i.bak \
    -e "s/version \".*\"/version \"${VERSION}\"/" \
    -e "s/PLACEHOLDER_DARWIN_ARM64/${HASHES[darwin_arm64]:-PLACEHOLDER_DARWIN_ARM64}/" \
    -e "s/PLACEHOLDER_DARWIN_AMD64/${HASHES[darwin_amd64]:-PLACEHOLDER_DARWIN_AMD64}/" \
    -e "s/PLACEHOLDER_LINUX_ARM64/${HASHES[linux_arm64]:-PLACEHOLDER_LINUX_ARM64}/" \
    -e "s/PLACEHOLDER_LINUX_AMD64/${HASHES[linux_amd64]:-PLACEHOLDER_LINUX_AMD64}/" \
    "$FORMULA"
rm -f "${FORMULA}.bak"

# Also update existing hashes (for subsequent runs)
for platform in "${PLATFORMS[@]}"; do
    if [[ "${HASHES[$platform]}" != PLACEHOLDER_* ]]; then
        # Replace any previous hash for this platform
        old_placeholder="PLACEHOLDER_${platform^^}"
        sed -i.bak "s/${old_placeholder}/${HASHES[$platform]}/" "$FORMULA"
        rm -f "${FORMULA}.bak"
    fi
done

echo "  Done."

# Commit and push
echo ""
echo "==> Committing and pushing"
cd "$HOMEBREW_REPO"
git add -A
git commit -m "sbproxy ${VERSION}" || {
    echo "  No changes to commit."
    exit 0
}
git push origin main

echo ""
echo "==> Homebrew formula updated for sbproxy v${VERSION}"
echo "  Install: brew tap soapbucket/sbproxy && brew install sbproxy"

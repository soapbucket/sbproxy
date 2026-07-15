#!/bin/sh
# Install sbproxy from GitHub releases
# Usage: curl -fsSL https://download.sbproxy.dev | sh
#
# Options:
#   SBPROXY_VERSION   - version to install (default: latest)
#   SBPROXY_INSTALL   - install directory (default: $HOME/.local/bin)
#   SBPROXY_SKIP_COSIGN - set to 1 to skip cosign verification even when cosign
#                         is installed (the sha256 check is never skippable)
#
# This is the front door of a gateway that will hold every provider API key in
# your environment. It downloads a binary over the network, so it verifies that
# binary against the SHA-256 we publish for every release before it runs, and
# refuses to install anything that does not match. Where cosign is present it
# also verifies the release signature. We verify the model weights we download
# elsewhere; there is no reason to hold the binary that reads them to a lower
# standard.

set -e

REPO="soapbucket/sbproxy"
INSTALL_DIR="${SBPROXY_INSTALL:-$HOME/.local/bin}"

main() {
    detect_platform
    resolve_version
    download_and_verify
    install_binary
    verify_install
}

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)  ;;
        darwin) ;;
        *)
            echo "Error: unsupported OS: $OS"
            echo "sbproxy supports linux and darwin (macOS)"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            echo "Error: unsupported architecture: $ARCH"
            echo "sbproxy supports amd64 and arm64"
            exit 1
            ;;
    esac

    # darwin/amd64 (Intel Mac) is not currently shipped: the macOS x86
    # runner pool stalls every release, and Apple Silicon has been the
    # default for new Macs since 2020. Intel Mac users have two options:
    #   1. Run the linux/amd64 binary in Docker (recommended)
    #   2. Build from source: cargo build --release --bin sbproxy
    if [ "$OS" = "darwin" ] && [ "$ARCH" = "amd64" ]; then
        echo "Error: pre-built sbproxy binaries are not published for darwin/amd64 (Intel Mac)."
        echo ""
        echo "Workarounds:"
        echo "  1. Run the linux/amd64 binary under Docker:"
        echo "       docker run --rm ghcr.io/soapbucket/sbproxy:latest --version"
        echo "  2. Build from source:"
        echo "       git clone https://github.com/soapbucket/sbproxy"
        echo "       cd sbproxy && cargo build --release --bin sbproxy"
        exit 1
    fi

    echo "Detected platform: ${OS}/${ARCH}"
}

resolve_version() {
    if [ -n "$SBPROXY_VERSION" ]; then
        VERSION="$SBPROXY_VERSION"
        echo "Using specified version: ${VERSION}"
        return
    fi

    echo "Fetching latest version..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"//;s/".*//')

    if [ -z "$VERSION" ]; then
        echo "Error: could not determine latest version"
        echo "Set SBPROXY_VERSION manually, e.g.: SBPROXY_VERSION=v0.1.0 sh install.sh"
        exit 1
    fi

    echo "Latest version: ${VERSION}"
}

# Compute the SHA-256 of a file, printing the bare lowercase hex digest.
#
# Consumers vary: coreutils on Linux ships sha256sum and usually not shasum,
# macOS ships shasum and openssl and usually not sha256sum. Try them in turn so
# the installer works on a stock box of either kind, and fail loudly rather than
# skipping the check if none is present.
sha256_of() {
    _file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$_file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$_file" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$_file" | awk '{print $NF}'
    else
        echo "Error: no SHA-256 tool found (need sha256sum, shasum, or openssl)." >&2
        echo "Cannot verify the download, so refusing to install." >&2
        exit 1
    fi
}

download_and_verify() {
    ARCHIVE="sbproxy_${OS}_${ARCH}.tar.gz"
    # SBPROXY_BASE_URL overrides the release host. It exists so the installer's
    # verification paths can be exercised against a local fixture (see
    # scripts/tests/install_verify.sh); in normal use it is unset and the
    # release assets are fetched from GitHub.
    BASE="${SBPROXY_BASE_URL:-https://github.com/${REPO}/releases/download/${VERSION}}"
    TMPDIR=$(mktemp -d)
    # Clean up the scratch dir on any exit, so a failed verification never
    # leaves a partial or unverified download behind.
    trap 'rm -rf "$TMPDIR"' EXIT INT TERM

    echo "Downloading ${BASE}/${ARCHIVE}..."
    if ! curl -fsSL "${BASE}/${ARCHIVE}" -o "${TMPDIR}/${ARCHIVE}"; then
        echo "Error: download failed"
        echo "Check that version ${VERSION} exists at:"
        echo "  https://github.com/${REPO}/releases"
        exit 1
    fi

    # --- Integrity: verify the published SHA-256 before trusting the bytes. ---
    echo "Fetching checksum..."
    if ! curl -fsSL "${BASE}/${ARCHIVE}.sha256" -o "${TMPDIR}/${ARCHIVE}.sha256"; then
        echo "Error: could not fetch ${ARCHIVE}.sha256 for ${VERSION}." >&2
        echo "Every release publishes this checksum; its absence means the release" >&2
        echo "is incomplete or the URL is wrong. Refusing to install unverified." >&2
        exit 1
    fi

    # The .sha256 is `shasum -a 256` text: `<64-hex>  <filename>`. Take the
    # first field, lowercase it, and require exactly 64 hex characters, so a
    # truncated or empty fetch is a hard failure rather than a vacuous pass.
    EXPECTED=$(awk '{print $1}' "${TMPDIR}/${ARCHIVE}.sha256" | tr 'A-F' 'a-f')
    if ! echo "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "Error: published checksum is malformed: '${EXPECTED}'" >&2
        exit 1
    fi

    ACTUAL=$(sha256_of "${TMPDIR}/${ARCHIVE}" | tr 'A-F' 'a-f')
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        echo "Error: checksum mismatch. The download does not match the published" >&2
        echo "SHA-256, so it is corrupt or tampered. Nothing has been installed." >&2
        echo "  expected: ${EXPECTED}" >&2
        echo "  actual:   ${ACTUAL}" >&2
        exit 1
    fi
    echo "Checksum verified: ${ACTUAL}"

    # --- Authenticity: verify the cosign signature when cosign is present. ---
    verify_signature

    echo "Extracting..."
    tar xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"

    if [ ! -f "${TMPDIR}/sbproxy" ]; then
        echo "Error: sbproxy binary not found in archive"
        exit 1
    fi
    STAGED_BINARY="${TMPDIR}/sbproxy"
    # The archive digest verified the tarball. Capture the extracted binary's
    # own digest so verify_install can confirm the installed file is unchanged
    # from the one we just checked, closing the gap between here and the move.
    STAGED_DIGEST=$(sha256_of "$STAGED_BINARY" | tr 'A-F' 'a-f')
}

verify_signature() {
    if [ "${SBPROXY_SKIP_COSIGN:-0}" = "1" ]; then
        echo "Skipping cosign verification (SBPROXY_SKIP_COSIGN=1)."
        return
    fi
    if ! command -v cosign >/dev/null 2>&1; then
        echo "Note: cosign is not installed, so the release signature was not"
        echo "checked. The SHA-256 above still verifies integrity. To also verify"
        echo "authenticity, install cosign and re-run, or follow SUPPLY-CHAIN.md."
        return
    fi

    echo "Verifying cosign signature..."
    if ! curl -fsSL "${BASE}/${ARCHIVE}.cosign.bundle" \
        -o "${TMPDIR}/${ARCHIVE}.cosign.bundle"; then
        echo "Error: cosign is installed but the signature bundle for ${VERSION}" >&2
        echo "could not be fetched. Refusing to install a release we cannot verify." >&2
        echo "Set SBPROXY_SKIP_COSIGN=1 to install on the checksum alone." >&2
        exit 1
    fi

    _identity="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}"
    if ! cosign verify-blob \
        --bundle "${TMPDIR}/${ARCHIVE}.cosign.bundle" \
        --certificate-identity "$_identity" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${TMPDIR}/${ARCHIVE}" >/dev/null 2>&1; then
        echo "Error: cosign signature verification failed for ${ARCHIVE}." >&2
        echo "The artifact is not a signature match for the official ${VERSION}" >&2
        echo "release identity. Nothing has been installed." >&2
        exit 1
    fi
    echo "Signature verified: ${_identity}"
}

install_binary() {
    mkdir -p "$INSTALL_DIR" 2>/dev/null || true

    if [ -w "$INSTALL_DIR" ]; then
        mv "$STAGED_BINARY" "${INSTALL_DIR}/sbproxy"
    else
        echo ""
        echo "Install directory ${INSTALL_DIR} requires elevated permissions."
        printf "Install with sudo? [y/N] "
        read -r REPLY
        if [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
            sudo mv "$STAGED_BINARY" "${INSTALL_DIR}/sbproxy"
        else
            echo "Aborted. You can set a custom path with:"
            echo "  SBPROXY_INSTALL=~/.local/bin curl -fsSL download.sbproxy.dev | sh"
            exit 1
        fi
    fi

    chmod +x "${INSTALL_DIR}/sbproxy"
}

verify_install() {
    # Confirm the bytes that landed on disk are the bytes we verified, not
    # merely that some binary named sbproxy runs. `EXPECTED` is the archive's
    # digest, so recompute the installed binary's digest and compare against the
    # copy still staged in TMPDIR before the trap removes it.
    if [ -n "${STAGED_DIGEST:-}" ]; then
        _installed=$(sha256_of "${INSTALL_DIR}/sbproxy" | tr 'A-F' 'a-f')
        if [ "$_installed" != "$STAGED_DIGEST" ]; then
            echo "Error: the installed binary's digest does not match the verified" >&2
            echo "download. Something altered it between verification and install." >&2
            exit 1
        fi
    fi

    if command -v sbproxy >/dev/null 2>&1; then
        INSTALLED_VERSION=$(sbproxy --version 2>/dev/null || echo "unknown")
        echo ""
        echo "📦 sbproxy installed successfully!"
        echo "   Version:  ${INSTALLED_VERSION}"
        echo "   Location: $(command -v sbproxy)"
        echo ""
        echo "Get started:"
        echo "  sbproxy serve -f sb.yml"
        echo ""
        echo "Docs: https://github.com/${REPO}"
    else
        echo ""
        echo "📦 sbproxy installed to ${INSTALL_DIR}/sbproxy"
        echo ""
        if echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
            echo "Run: sbproxy --version"
        else
            echo "Note: ${INSTALL_DIR} is not in your PATH."
            echo "Add it with: export PATH=\"${INSTALL_DIR}:\$PATH\""
        fi
    fi
}

main

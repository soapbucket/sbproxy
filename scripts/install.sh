#!/bin/sh
# Install sbproxy from GitHub releases
# Usage: curl -fsSL https://download.sbproxy.dev | sh
#
# Options:
#   SBPROXY_VERSION   - version to install (default: latest)
#   SBPROXY_INSTALL   - install directory (default: /usr/local/bin)

set -e

REPO="soapbucket/sbproxy"
INSTALL_DIR="${SBPROXY_INSTALL:-/usr/local/bin}"

main() {
    detect_platform
    resolve_version
    download_and_install
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

download_and_install() {
    ARCHIVE="sbproxy_${OS}_${ARCH}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
    TMPDIR=$(mktemp -d)

    echo "Downloading ${URL}..."
    if ! curl -fsSL "$URL" -o "${TMPDIR}/${ARCHIVE}"; then
        echo "Error: download failed"
        echo "Check that version ${VERSION} exists at:"
        echo "  https://github.com/${REPO}/releases"
        rm -rf "$TMPDIR"
        exit 1
    fi

    echo "Extracting..."
    tar xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"

    if [ ! -f "${TMPDIR}/sbproxy" ]; then
        echo "Error: sbproxy binary not found in archive"
        rm -rf "$TMPDIR"
        exit 1
    fi

    # Install the binary
    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/sbproxy" "${INSTALL_DIR}/sbproxy"
    else
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "${TMPDIR}/sbproxy" "${INSTALL_DIR}/sbproxy"
    fi

    chmod +x "${INSTALL_DIR}/sbproxy"
    rm -rf "$TMPDIR"
}

verify_install() {
    if command -v sbproxy >/dev/null 2>&1; then
        INSTALLED_VERSION=$(sbproxy --version 2>/dev/null || echo "unknown")
        echo ""
        echo "sbproxy installed successfully!"
        echo "  Version:  ${INSTALLED_VERSION}"
        echo "  Location: $(command -v sbproxy)"
        echo ""
        echo "Get started:"
        echo "  sbproxy serve -f sb.yml"
        echo ""
        echo "Docs: https://github.com/${REPO}"
    else
        echo ""
        echo "sbproxy installed to ${INSTALL_DIR}/sbproxy"
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

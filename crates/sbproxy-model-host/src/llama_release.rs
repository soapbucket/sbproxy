// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! llama.cpp engine acquisition (WOR-1656).
//!
//! The `serve:` argv template for `llama-server` already exists
//! ([`crate::launch::build_launch_spec`]); this is how the binary is
//! obtained. Resolution is PATH-first (document `brew install
//! llama.cpp` / the distro package), with an optional pinned-release
//! fallback: a specific ggml-org/llama.cpp release asset for the host
//! platform, verified against a sha256 before use. The pin keeps the
//! security posture (WOR-1663): no arbitrary binary, a known tag and a
//! known digest.
//!
//! The platform detection, asset-URL construction, and PATH lookup are
//! pure and unit-tested. The actual download + unzip is behind the
//! `weights` feature (it reuses the reqwest fetch) and shells out to
//! `unzip`, so no archive crate is pulled into the lean build.

use std::path::PathBuf;

/// A host platform ggml-org publishes a llama.cpp binary asset for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux x86-64.
    LinuxX64,
    /// macOS Apple Silicon.
    MacOsArm64,
    /// macOS Intel.
    MacOsX64,
}

impl Platform {
    /// Detect the current host platform, or `None` when it is not one
    /// ggml-org ships a prebuilt binary for.
    pub fn detect() -> Option<Self> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => Some(Platform::LinuxX64),
            ("macos", "aarch64") => Some(Platform::MacOsArm64),
            ("macos", "x86_64") => Some(Platform::MacOsX64),
            _ => None,
        }
    }

    /// The ggml-org release asset infix for this platform (the
    /// `ubuntu-x64` in `llama-<tag>-bin-ubuntu-x64.zip`).
    fn asset_infix(self) -> &'static str {
        match self {
            Platform::LinuxX64 => "ubuntu-x64",
            Platform::MacOsArm64 => "macos-arm64",
            Platform::MacOsX64 => "macos-x64",
        }
    }
}

/// The download URL for a pinned ggml-org/llama.cpp release binary
/// asset. `tag` is a release tag (for example `b4589`); it must not be
/// `latest`, so the acquisition stays pinned.
pub fn asset_url(tag: &str, platform: Platform) -> Result<String, String> {
    if tag.trim().is_empty() || tag == "latest" {
        return Err(format!("llama.cpp release tag must be pinned, not '{tag}'"));
    }
    Ok(format!(
        "https://github.com/ggml-org/llama.cpp/releases/download/{tag}/llama-{tag}-bin-{}.zip",
        platform.asset_infix()
    ))
}

/// Find `name` on `PATH`, returning its full path. This is the
/// preferred acquisition: an operator-installed `llama-server`.
pub fn resolve_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Ensure a `llama-server` binary is available: prefer one on `PATH`,
/// else download the pinned release for this platform into
/// `cache_dir`, verify its sha256, unzip it, and return the extracted
/// `llama-server` path. Behind the `weights` feature (the download
/// reuses reqwest); shells out to `unzip`.
#[cfg(feature = "weights")]
pub async fn ensure_llama_server(
    cache_dir: &std::path::Path,
    tag: &str,
    expected_sha256: &str,
) -> Result<PathBuf, String> {
    if let Some(p) = resolve_on_path("llama-server") {
        return Ok(p);
    }
    let platform = Platform::detect().ok_or_else(|| {
        format!(
            "no prebuilt llama.cpp binary for {}/{}; install llama.cpp on PATH",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let url = asset_url(tag, platform)?;
    let dest_dir = cache_dir.join("llama.cpp").join(tag);
    tokio::fs::create_dir_all(&dest_dir)
        .await
        .map_err(|e| format!("create {}: {e}", dest_dir.display()))?;
    let zip_path = dest_dir.join("llama.zip");

    // Download.
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("download {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download {url}: {e}"))?;
    let bytes = resp.bytes().await.map_err(|e| format!("read {url}: {e}"))?;
    tokio::fs::write(&zip_path, &bytes)
        .await
        .map_err(|e| format!("write {}: {e}", zip_path.display()))?;

    // Verify the pinned digest before using it.
    crate::weights::verify_sha256(&zip_path, expected_sha256)?;

    // Extract (shell out to unzip to avoid an archive crate dependency).
    let status = tokio::process::Command::new("unzip")
        .args(["-o", "-q"])
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest_dir)
        .status()
        .await
        .map_err(|e| format!("unzip: {e}"))?;
    if !status.success() {
        return Err(format!("unzip of {} failed", zip_path.display()));
    }

    // The binary lands under a bin/ dir in the archive.
    for candidate in [
        dest_dir.join("build/bin/llama-server"),
        dest_dir.join("bin/llama-server"),
        dest_dir.join("llama-server"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "llama-server not found in the extracted release under {}",
        dest_dir.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_url_is_pinned_and_platform_specific() {
        assert_eq!(
            asset_url("b4589", Platform::LinuxX64).unwrap(),
            "https://github.com/ggml-org/llama.cpp/releases/download/b4589/llama-b4589-bin-ubuntu-x64.zip"
        );
        assert_eq!(
            asset_url("b4589", Platform::MacOsArm64).unwrap(),
            "https://github.com/ggml-org/llama.cpp/releases/download/b4589/llama-b4589-bin-macos-arm64.zip"
        );
    }

    #[test]
    fn unpinned_tag_is_rejected() {
        assert!(asset_url("latest", Platform::LinuxX64).is_err());
        assert!(asset_url("", Platform::LinuxX64).is_err());
    }

    #[test]
    fn resolve_on_path_finds_a_known_binary() {
        // `sh` is on PATH on every unix CI host; use it to prove the
        // lookup works without depending on llama-server being present.
        #[cfg(unix)]
        {
            assert!(resolve_on_path("sh").is_some());
            assert!(resolve_on_path("definitely-not-a-real-binary-xyz").is_none());
        }
    }

    #[test]
    fn detect_returns_a_known_platform_on_supported_hosts() {
        // On the CI/dev hosts (linux-x64, macos-arm64) detection is Some;
        // we only assert it does not panic and is consistent with the
        // build target.
        let p = Platform::detect();
        if std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64" {
            assert_eq!(p, Some(Platform::LinuxX64));
        }
    }
}

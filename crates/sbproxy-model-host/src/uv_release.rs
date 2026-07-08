// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! `uv` acquisition for the vLLM engine (WOR-1801 / WOR-1812).
//!
//! vLLM is a Python package, not a single-binary release, so it cannot be
//! fetched the way llama.cpp is. Instead sbproxy fetches `uv` (Astral's
//! single-binary Python package manager) and runs vLLM through
//! `uv tool run` (a.k.a. `uvx`): an ephemeral, cached environment that uv
//! provisions on first use, bringing its own Python if the host lacks a
//! suitable one. That yields a CUDA-enabled vLLM (the default wheel) on a
//! box that carries only the NVIDIA driver, which is the GPU path the
//! Vulkan-only llama.cpp prebuilt cannot take on some images.
//!
//! Like the llama.cpp release, `uv` is a pinned GitHub release asset,
//! extracted with `tar`. The pure URL/target logic is unit-tested; the
//! fetch is behind the `weights` feature.

#[cfg(feature = "weights")]
use std::path::PathBuf;

use crate::llama_release::resolve_on_path;

/// The default pinned `uv` release used when the acquire block does not
/// pin its own uv version. `uv` itself is pinned here; the vLLM *package*
/// version is pinned separately (`engines.vllm.acquire.version`).
pub const DEFAULT_UV_VERSION: &str = "0.11.28";

/// The `uv` release target triple for this host, or `None` if uv ships no
/// prebuilt for it.
fn uv_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        _ => None,
    }
}

/// The download URL for a pinned `uv` release binary for this host.
/// `version` is a uv release tag (for example `0.11.28`).
pub fn uv_asset_url(version: &str) -> Result<String, String> {
    if version.trim().is_empty() {
        return Err("uv version must be pinned".to_string());
    }
    let target = uv_target().ok_or_else(|| {
        format!(
            "no prebuilt uv for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    Ok(format!(
        "https://github.com/astral-sh/uv/releases/download/{version}/uv-{target}.tar.gz"
    ))
}

/// Ensure a `uv` binary is available: prefer one on `PATH`, else fetch the
/// pinned release into `cache_dir` and return the extracted path. Behind
/// the `weights` feature; shells out to `tar`.
#[cfg(feature = "weights")]
pub async fn ensure_uv(cache_dir: &std::path::Path, version: &str) -> Result<PathBuf, String> {
    if let Some(p) = resolve_on_path("uv") {
        return Ok(p);
    }
    let url = uv_asset_url(version)?;
    let dest_dir = cache_dir.join("uv").join(version);
    tokio::fs::create_dir_all(&dest_dir)
        .await
        .map_err(|e| format!("create {}: {e}", dest_dir.display()))?;

    // Reuse a cached extraction rather than re-downloading every launch.
    if let Some(p) = crate::llama_release::find_file_named(&dest_dir, "uv") {
        return Ok(p);
    }

    let archive = dest_dir.join("uv.tar.gz");
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("download {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download {url}: {e}"))?;
    let bytes = resp.bytes().await.map_err(|e| format!("read {url}: {e}"))?;
    tokio::fs::write(&archive, &bytes)
        .await
        .map_err(|e| format!("write {}: {e}", archive.display()))?;

    let status = tokio::process::Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(&dest_dir)
        .status()
        .await
        .map_err(|e| format!("tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar extract of {} failed", archive.display()));
    }
    crate::llama_release::find_file_named(&dest_dir, "uv").ok_or_else(|| {
        format!(
            "uv not found in the extracted release under {}",
            dest_dir.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_asset_url_is_pinned_and_targeted() {
        // On CI/dev hosts (linux-x64, macos-arm64) the target resolves.
        if let Ok(url) = uv_asset_url("0.11.28") {
            assert!(url.contains("astral-sh/uv/releases/download/0.11.28/uv-"));
            assert!(url.ends_with(".tar.gz"));
        }
    }

    #[test]
    fn empty_uv_version_is_rejected() {
        assert!(uv_asset_url("").is_err());
    }
}

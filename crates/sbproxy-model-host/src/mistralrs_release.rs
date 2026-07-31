// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! mistral.rs engine acquisition (WOR-1861).
//!
//! Upstream ships pinned per-platform release binaries from v0.9.0
//! (a single `mistralrs` CLI binary per tarball), so this lane follows
//! the llama.cpp acquisition posture exactly: PATH-first, then a
//! pinned-tag prebuilt release with a checked-in SHA-256 for every
//! supported asset. No arbitrary binary or command line (WOR-1663).
//!
//! Upstream publishes CUDA assets per CUDA toolkit flavour and per GPU
//! compute capability (`mistralrs-cuda128-sm89-...`). This module pins
//! one flavour, `MISTRALRS_CUDA_VARIANT` (cuda128): the oldest published
//! CUDA build, which has the widest driver compatibility (the NVIDIA
//! driver must support CUDA 12.8). The compute capability comes from the
//! GPU probe, so asset selection stays deterministic per host.
//!
//! Platform detection, asset naming, and URL construction are pure and
//! unit-tested. The download + extract half is behind the `weights`
//! feature and shells out to `tar`, mirroring
//! `crate::llama_release::ensure_llama_server`.

#[cfg(any(feature = "weights", test))]
use std::path::PathBuf;

use crate::config::EngineAccel;
#[cfg(any(feature = "weights", test))]
use crate::llama_release::is_executable_file;
use crate::llama_release::Platform;

#[cfg(feature = "weights")]
use fs2::FileExt;

/// CUDA release tarballs bundle the toolkit runtime and exceed 1 GiB.
#[cfg(feature = "weights")]
const MAX_MISTRALRS_RELEASE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
#[cfg(any(feature = "weights", test))]
const UNPINNED_RELEASE_MARKER: &str = "digest-unpinned";

/// The pinned mistral.rs release tag used when
/// `engines.mistralrs.acquire.version` is unset. crates.io still serves
/// 0.8.1; v0.9.0 is the first upstream release that publishes prebuilt
/// binaries, which is what this subprocess lane exists to consume.
/// Operators pinning a different tag must provide `acquire.sha256`,
/// since only the default tag's assets have built-in digests.
pub const DEFAULT_MISTRALRS_RELEASE_TAG: &str = "v0.9.0";

/// The pinned CUDA flavour of the upstream release matrix. cuda128 is
/// the oldest flavour upstream publishes, so it runs on the widest
/// driver range (driver-supported CUDA >= 12.8); newer flavours only
/// relax that on newer fleets and can be reached with an explicit
/// `acquire.version`-tag + `acquire.sha256` pin if ever needed.
const MISTRALRS_CUDA_VARIANT: &str = "cuda128";

/// x86-64 compute capabilities upstream publishes a cuda128 asset for
/// (sm80 A100, sm86 A10/A40, sm89 L4/Ada, sm90 H100, sm100 B200,
/// sm120 RTX 6000 Blackwell).
const MISTRALRS_CUDA_SMS: &[u32] = &[80, 86, 89, 90, 100, 120];

/// Built-in digest for one supported asset of the default pinned tag,
/// computed from the published v0.9.0 release assets.
const DEFAULT_MISTRALRS_ASSET_SHA256: &[(&str, &str)] = &[
    (
        "mistralrs-metal-aarch64-apple-darwin.tar.gz",
        "051818694b1de1d8850b6eecf7b6b7a83c4a933a6a64605285157166c8288638",
    ),
    (
        "mistralrs-cpu-x86_64-unknown-linux-gnu.tar.gz",
        "f2fc7e319ef1b9124ad89353de676fce8063545e1b7daae56bb9a2fa9b89a63f",
    ),
    (
        "mistralrs-cuda128-sm80-x86_64-unknown-linux-gnu.tar.gz",
        "006ba5cc43e691588739bc958076781d590613568fbf4f35d6e158b9829cd607",
    ),
    (
        "mistralrs-cuda128-sm86-x86_64-unknown-linux-gnu.tar.gz",
        "e50baa81611abec613dbbce3b8093cf68f1fd5e0ae6d46e965ca61b875a475e8",
    ),
    (
        "mistralrs-cuda128-sm89-x86_64-unknown-linux-gnu.tar.gz",
        "ffd0e3820f981e33677a8a484ed481b81ad1ff3ec5112f3f439dab2d2dc1f423",
    ),
    (
        "mistralrs-cuda128-sm90-x86_64-unknown-linux-gnu.tar.gz",
        "4542021e2e211a58899cff7dcfd0ce6d0061e732c68de24dfb73ed3f924793eb",
    ),
    (
        "mistralrs-cuda128-sm100-x86_64-unknown-linux-gnu.tar.gz",
        "de0a03a4371bfe9de1b3b1be74baf28c1761d57d04d388dad47a38bc9a9c8998",
    ),
    (
        "mistralrs-cuda128-sm120-x86_64-unknown-linux-gnu.tar.gz",
        "d91c858b4648d4fbdb70966a1ba79bcf9aa3a97c9ab45b5f14a61ea4ea87217b",
    ),
];

/// The release asset filename for a platform + acceleration flavour.
/// `compute_capability` is the probed GPU capability, consulted only on
/// the CUDA path (`sm{major}{minor}` names the asset). Errors name the
/// unsupported combination and the operator's alternatives.
pub fn release_asset(
    platform: Platform,
    accel: EngineAccel,
    compute_capability: Option<(u32, u32)>,
) -> Result<String, String> {
    match platform {
        // The Metal build is the only Apple asset; it is the CPU path
        // on Apple Silicon too (Metal is built in, like llama.cpp's
        // macos asset).
        Platform::MacOsArm64 => Ok("mistralrs-metal-aarch64-apple-darwin.tar.gz".to_string()),
        Platform::MacOsX64 => Err(
            "mistral.rs publishes no Intel-mac prebuilt; install `mistralrs` on PATH \
             (upstream's installer builds from source there) or point \
             engines.mistralrs.acquire.path at a vetted binary"
                .to_string(),
        ),
        Platform::LinuxX64 => match accel {
            EngineAccel::Vulkan => Err(
                "mistral.rs publishes no Vulkan asset; use accel cuda or cpu, or llama.cpp \
                 for the Vulkan path"
                    .to_string(),
            ),
            EngineAccel::Metal => {
                Err("Metal acceleration does not exist on Linux; use cuda or cpu".to_string())
            }
            EngineAccel::Cuda => cuda_asset(compute_capability),
            EngineAccel::Auto => match compute_capability {
                Some(_) => cuda_asset(compute_capability),
                None => Ok("mistralrs-cpu-x86_64-unknown-linux-gnu.tar.gz".to_string()),
            },
            EngineAccel::Cpu => Ok("mistralrs-cpu-x86_64-unknown-linux-gnu.tar.gz".to_string()),
        },
    }
}

fn cuda_asset(compute_capability: Option<(u32, u32)>) -> Result<String, String> {
    let Some((major, minor)) = compute_capability else {
        return Err(
            "mistral.rs CUDA acquisition needs the GPU compute capability, and no NVIDIA \
             GPU was probed; use accel: cpu or install `mistralrs` on PATH"
                .to_string(),
        );
    };
    let sm = major * 10 + minor;
    if !MISTRALRS_CUDA_SMS.contains(&sm) {
        return Err(format!(
            "mistral.rs publishes no {MISTRALRS_CUDA_VARIANT} asset for compute capability \
             {major}.{minor} (sm{sm}); published: {}. Install `mistralrs` on PATH or use \
             engines.mistralrs.acquire.path",
            MISTRALRS_CUDA_SMS
                .iter()
                .map(|sm| format!("sm{sm}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(format!(
        "mistralrs-{MISTRALRS_CUDA_VARIANT}-sm{sm}-x86_64-unknown-linux-gnu.tar.gz"
    ))
}

/// Built-in digest for one supported asset of the default pinned tag.
/// Only [`DEFAULT_MISTRALRS_RELEASE_TAG`] assets have digests; any
/// other tag requires an explicit `acquire.sha256`.
pub(crate) fn default_release_sha256(tag: &str, asset: &str) -> Option<&'static str> {
    if tag != DEFAULT_MISTRALRS_RELEASE_TAG {
        return None;
    }
    DEFAULT_MISTRALRS_ASSET_SHA256
        .iter()
        .find(|(name, _)| *name == asset)
        .map(|(_, digest)| *digest)
}

/// The download URL for a pinned mistral.rs release asset. `tag` must be
/// a pinned identifier, never `latest`.
pub fn asset_url(tag: &str, asset: &str) -> Result<String, String> {
    crate::llama_release::validate_pinned_tag(tag)?;
    Ok(format!(
        "https://github.com/EricLBuehler/mistral.rs/releases/download/{tag}/{asset}"
    ))
}

/// Ensure a `mistralrs` binary is available: prefer one on `PATH`, else
/// download the pinned release asset into `cache_dir`, verify its
/// sha256 (when a digest is pinned), extract it, and return the
/// extracted `mistralrs` path. Behind the `weights` feature; shells out
/// to `tar`. Mirrors [`crate::llama_release::ensure_llama_server`].
#[cfg(feature = "weights")]
pub async fn ensure_mistralrs_binary(
    cache_dir: &std::path::Path,
    tag: &str,
    asset: &str,
    expected_sha256: Option<&str>,
) -> Result<PathBuf, String> {
    use crate::llama_release::resolve_on_path;

    if let Some(p) = resolve_on_path("mistralrs") {
        return Ok(p);
    }
    let url = asset_url(tag, asset)?;
    let ready_dir = cache_dir.join("mistral.rs").join(tag).join(asset);
    if let Some(binary) = cached_release_binary(&ready_dir, expected_sha256) {
        return Ok(binary);
    }

    let lock_path = cache_dir
        .join("locks")
        .join(format!("mistralrs-release-{tag}-{asset}.lock"));
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let lock = tokio::task::spawn_blocking(move || open_release_lock(&lock_path))
        .await
        .map_err(|e| format!("join mistral.rs release lock: {e}"))??;
    if let Some(binary) = cached_release_binary(&ready_dir, expected_sha256) {
        drop(lock);
        return Ok(binary);
    }

    let staging = cache_dir
        .join("staging")
        .join(format!("mistralrs-release-{tag}-{}", ulid::Ulid::new()));
    tokio::fs::create_dir_all(&staging)
        .await
        .map_err(|e| format!("create {}: {e}", staging.display()))?;
    let result = install_release(&url, &staging, &ready_dir, expected_sha256).await;
    let _ = tokio::fs::remove_dir_all(&staging).await;
    drop(lock);
    result
}

#[cfg(feature = "weights")]
async fn install_release(
    url: &str,
    staging: &std::path::Path,
    ready_dir: &std::path::Path,
    expected_sha256: Option<&str>,
) -> Result<PathBuf, String> {
    let archive_path = staging.join("mistralrs.tar.gz");

    // Download through the engine-artifact egress gate.
    crate::artifact::authorize_engine_download(url)?;
    let resp = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|e| format!("download {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download {url}: {e}"))?;
    if resp
        .content_length()
        .is_some_and(|length| length > MAX_MISTRALRS_RELEASE_BYTES)
    {
        return Err(format!(
            "mistral.rs release exceeds {MAX_MISTRALRS_RELEASE_BYTES} bytes"
        ));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("read {url}: {e}"))?;
    if bytes.len() as u64 > MAX_MISTRALRS_RELEASE_BYTES {
        return Err(format!(
            "mistral.rs release exceeds {MAX_MISTRALRS_RELEASE_BYTES} bytes"
        ));
    }
    tokio::fs::write(&archive_path, &bytes)
        .await
        .map_err(|e| format!("write {}: {e}", archive_path.display()))?;

    // Verify the pinned digest before using it, when one is pinned.
    match expected_sha256 {
        Some(hex) => crate::weights::verify_sha256(&archive_path, hex)?,
        None => tracing::warn!(
            url,
            "mistral.rs release fetched without a pinned sha256; set \
             engines.mistralrs.acquire.sha256 to verify the download"
        ),
    }

    // Extract: the tarball carries the `mistralrs` binary at its root.
    let status = tokio::process::Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(staging)
        .status()
        .await
        .map_err(|e| format!("tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar extract of {} failed", archive_path.display()));
    }

    let binary = [staging.join("mistralrs"), staging.join("bin/mistralrs")]
        .into_iter()
        .find(|candidate| is_executable_file(candidate))
        .or_else(|| {
            crate::llama_release::find_file_named(staging, "mistralrs")
                .filter(|path| is_executable_file(path))
        })
        .ok_or_else(|| {
            format!(
                "executable mistralrs not found in the extracted release under {}",
                staging.display()
            )
        })?;
    let relative_binary = binary
        .strip_prefix(staging)
        .map_err(|e| format!("resolve extracted mistralrs path: {e}"))?
        .to_path_buf();
    let marker = expected_sha256.unwrap_or(UNPINNED_RELEASE_MARKER);
    tokio::fs::write(staging.join(".archive.sha256"), marker)
        .await
        .map_err(|e| format!("write mistral.rs release digest marker: {e}"))?;

    if ready_dir.exists() {
        tokio::fs::remove_dir_all(ready_dir)
            .await
            .map_err(|e| format!("remove stale {}: {e}", ready_dir.display()))?;
    }
    if let Some(parent) = ready_dir.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    tokio::fs::rename(staging, ready_dir)
        .await
        .map_err(|e| format!("publish mistral.rs release: {e}"))?;
    let published = ready_dir.join(relative_binary);
    if !is_executable_file(&published) {
        return Err(format!(
            "published mistralrs is not executable at {}",
            published.display()
        ));
    }
    Ok(published)
}

#[cfg(any(feature = "weights", test))]
fn cached_release_binary(
    ready_dir: &std::path::Path,
    expected_sha256: Option<&str>,
) -> Option<PathBuf> {
    let marker = std::fs::read_to_string(ready_dir.join(".archive.sha256")).ok()?;
    if marker.trim() != expected_sha256.unwrap_or(UNPINNED_RELEASE_MARKER) {
        return None;
    }
    crate::llama_release::find_file_named(ready_dir, "mistralrs")
        .filter(|path| is_executable_file(path))
}

#[cfg(feature = "weights")]
fn open_release_lock(path: &std::path::Path) -> Result<std::fs::File, String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| format!("open mistral.rs release lock {}: {e}", path.display()))?;
    file.lock_exclusive()
        .map_err(|e| format!("lock mistral.rs release {}: {e}", path.display()))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_selection_is_platform_and_capability_specific() {
        assert_eq!(
            release_asset(Platform::MacOsArm64, EngineAccel::Auto, None).unwrap(),
            "mistralrs-metal-aarch64-apple-darwin.tar.gz"
        );
        // Metal is built into the one Apple asset, whatever accel says.
        assert_eq!(
            release_asset(Platform::MacOsArm64, EngineAccel::Metal, None).unwrap(),
            "mistralrs-metal-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            release_asset(Platform::LinuxX64, EngineAccel::Cpu, None).unwrap(),
            "mistralrs-cpu-x86_64-unknown-linux-gnu.tar.gz"
        );
        // The L4 (sm89) picks the pinned cuda128 flavour.
        assert_eq!(
            release_asset(Platform::LinuxX64, EngineAccel::Cuda, Some((8, 9))).unwrap(),
            "mistralrs-cuda128-sm89-x86_64-unknown-linux-gnu.tar.gz"
        );
        // Auto on a GPU host is the CUDA asset; without a GPU, CPU.
        assert_eq!(
            release_asset(Platform::LinuxX64, EngineAccel::Auto, Some((9, 0))).unwrap(),
            "mistralrs-cuda128-sm90-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            release_asset(Platform::LinuxX64, EngineAccel::Auto, None).unwrap(),
            "mistralrs-cpu-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn unsupported_targets_error_with_alternatives() {
        // Intel mac: no upstream asset.
        let error = release_asset(Platform::MacOsX64, EngineAccel::Auto, None).unwrap_err();
        assert!(error.contains("PATH"), "{error}");
        // Vulkan: llama.cpp's lane, not mistral.rs's.
        let error = release_asset(Platform::LinuxX64, EngineAccel::Vulkan, None).unwrap_err();
        assert!(error.contains("llama.cpp"), "{error}");
        // A compute capability without a published build (sm75 T4).
        let error = release_asset(Platform::LinuxX64, EngineAccel::Cuda, Some((7, 5))).unwrap_err();
        assert!(error.contains("sm75"), "{error}");
        assert!(error.contains("sm89"), "{error}");
        // CUDA requested with no probed GPU.
        let error = release_asset(Platform::LinuxX64, EngineAccel::Cuda, None).unwrap_err();
        assert!(error.contains("compute capability"), "{error}");
    }

    #[test]
    fn asset_url_is_pinned_and_rejects_latest() {
        assert_eq!(
            asset_url(
                DEFAULT_MISTRALRS_RELEASE_TAG,
                "mistralrs-metal-aarch64-apple-darwin.tar.gz"
            )
            .unwrap(),
            "https://github.com/EricLBuehler/mistral.rs/releases/download/v0.9.0/mistralrs-metal-aarch64-apple-darwin.tar.gz"
        );
        assert!(asset_url("latest", "mistralrs-metal-aarch64-apple-darwin.tar.gz").is_err());
    }

    #[test]
    fn supported_assets_of_the_default_tag_have_built_in_digests() {
        for asset in [
            "mistralrs-metal-aarch64-apple-darwin.tar.gz",
            "mistralrs-cpu-x86_64-unknown-linux-gnu.tar.gz",
        ] {
            let digest = default_release_sha256(DEFAULT_MISTRALRS_RELEASE_TAG, asset);
            assert!(digest.is_some(), "missing built-in digest for {asset}");
            assert_eq!(digest.unwrap().len(), 64);
        }
        // Non-default tags never get a built-in digest.
        assert_eq!(
            default_release_sha256("v0.8.1", "mistralrs-metal-aarch64-apple-darwin.tar.gz"),
            None
        );
    }

    #[test]
    fn default_tag_is_pinned_and_never_latest() {
        assert_ne!(DEFAULT_MISTRALRS_RELEASE_TAG, "latest");
        crate::llama_release::validate_pinned_tag(DEFAULT_MISTRALRS_RELEASE_TAG).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn verified_release_cache_hit_requires_the_matching_digest_marker() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let binary = ready.join("mistralrs");
        std::fs::create_dir_all(&ready).unwrap();
        std::fs::write(&binary, b"fixture").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pinned = default_release_sha256(
            DEFAULT_MISTRALRS_RELEASE_TAG,
            "mistralrs-metal-aarch64-apple-darwin.tar.gz",
        )
        .unwrap();
        std::fs::write(ready.join(".archive.sha256"), pinned).unwrap();

        assert_eq!(cached_release_binary(&ready, Some(pinned)), Some(binary));
        assert_eq!(cached_release_binary(&ready, Some("deadbeef")), None);
        assert_eq!(cached_release_binary(&ready, None), None);
    }
}

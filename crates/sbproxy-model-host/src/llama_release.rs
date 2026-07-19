// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! llama.cpp engine acquisition (WOR-1656).
//!
//! The `serve:` argv template for `llama-server` already exists
//! ([`crate::launch::build_launch_spec`]); this is how the binary is
//! obtained. Ordinary release acquisition is PATH-first (document `brew
//! install llama.cpp` / the distro package), with an optional pinned
//! release fallback for the host platform. CUDA uses the separate fixed,
//! digest-pinned source builder because upstream does not publish a CUDA
//! Linux binary. The pins keep the security posture (WOR-1663): no
//! arbitrary binary or command line.
//!
//! The platform detection, asset-URL construction, and PATH lookup are
//! pure and unit-tested. The actual download + extract is behind the
//! `weights` feature (it reuses the reqwest fetch) and shells out to
//! `tar`, so no archive crate is pulled into the lean build.

use std::path::PathBuf;

#[cfg(feature = "weights")]
use fs2::FileExt;

#[cfg(feature = "weights")]
const MAX_LLAMA_RELEASE_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(any(feature = "weights", test))]
const UNPINNED_RELEASE_MARKER: &str = "digest-unpinned";

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

    /// The asset infix for a requested acceleration flavour (WOR-1801).
    /// macOS assets already carry Metal. Linux Vulkan has a release asset,
    /// while CUDA must use the separately verified source-build path.
    fn asset_infix_accel(self, accel: crate::config::EngineAccel) -> Result<&'static str, String> {
        use crate::config::EngineAccel::*;
        match self {
            Platform::MacOsArm64 => Ok("macos-arm64"),
            Platform::MacOsX64 => Ok("macos-x64"),
            Platform::LinuxX64 => match accel {
                Cuda => {
                    Err("llama.cpp CUDA acquisition requires the pinned source build".to_string())
                }
                Vulkan => Ok("ubuntu-vulkan-x64"),
                Auto | Cpu | Metal => Ok("ubuntu-x64"),
            },
        }
    }
}

/// The default pinned llama.cpp release tag used when
/// `engines.llama_cpp.acquire.version` is unset (WOR-1801). The supported
/// prebuilt assets for this tag have built-in digests. Operators using a
/// different tag must provide `acquire.sha256` to verify its asset.
///
/// Pinned to a tag that ships the `ubuntu-vulkan-x64` asset (the Linux
/// GPU path): the older `b4589` had only a CPU `ubuntu-x64` build, so a
/// `cuda`/`vulkan` acquisition 404'd on Linux. From this tag the macOS
/// and Linux assets are `.tar.gz` (they were `.zip` at `b4589`).
pub const DEFAULT_LLAMA_RELEASE_TAG: &str = "b9905";

const DEFAULT_LLAMA_MACOS_ARM64_SHA256: &str =
    "0d3deb02fd7912c8ef360fa33b3b4a8c97967a3ac703c0ed7d5edd3680723ea8";
const DEFAULT_LLAMA_MACOS_X64_SHA256: &str =
    "5910cec4ce883d0ddef39974a54a5c9569c4c8b3d13b5e79dfcb32ffda19e44e";
const DEFAULT_LLAMA_LINUX_X64_SHA256: &str =
    "69f1496c1eda919097668db49e529819e4eda9e8e3d504f90c680fed3587f5b0";
const DEFAULT_LLAMA_LINUX_VULKAN_X64_SHA256: &str =
    "81492d7844bcb40c4c025b826dced6b3faa6e484863482d6bd255c84db53bd55";

/// Built-in digest for one supported default release asset.
pub(crate) fn default_release_sha256(
    tag: &str,
    platform: Platform,
    accel: crate::config::EngineAccel,
) -> Option<&'static str> {
    use crate::config::EngineAccel;

    if tag != DEFAULT_LLAMA_RELEASE_TAG {
        return None;
    }
    match (platform, accel) {
        (Platform::MacOsArm64, _) => Some(DEFAULT_LLAMA_MACOS_ARM64_SHA256),
        (Platform::MacOsX64, _) => Some(DEFAULT_LLAMA_MACOS_X64_SHA256),
        (Platform::LinuxX64, EngineAccel::Vulkan) => Some(DEFAULT_LLAMA_LINUX_VULKAN_X64_SHA256),
        (Platform::LinuxX64, EngineAccel::Cuda) => None,
        (Platform::LinuxX64, _) => Some(DEFAULT_LLAMA_LINUX_X64_SHA256),
    }
}

/// The archive extension for a platform's release asset. macOS and Linux
/// assets are `.tar.gz`; only Windows (unsupported here) would be `.zip`.
fn archive_ext(_platform: Platform) -> &'static str {
    "tar.gz"
}

/// The download URL for a pinned ggml-org/llama.cpp release binary asset
/// for a requested acceleration flavour (WOR-1801). Like [`asset_url`]
/// but accel-aware. Linux CUDA is rejected because it uses source builds.
pub fn asset_url_accel(
    tag: &str,
    platform: Platform,
    accel: crate::config::EngineAccel,
) -> Result<String, String> {
    validate_pinned_tag(tag)?;
    Ok(format!(
        "https://github.com/ggml-org/llama.cpp/releases/download/{tag}/llama-{tag}-bin-{}.{}",
        platform.asset_infix_accel(accel)?,
        archive_ext(platform)
    ))
}

/// The download URL for a pinned ggml-org/llama.cpp release binary
/// asset. `tag` is a release tag (for example `b9905`); it must not be
/// `latest`, so the acquisition stays pinned.
pub fn asset_url(tag: &str, platform: Platform) -> Result<String, String> {
    validate_pinned_tag(tag)?;
    Ok(format!(
        "https://github.com/ggml-org/llama.cpp/releases/download/{tag}/llama-{tag}-bin-{}.{}",
        platform.asset_infix(),
        archive_ext(platform)
    ))
}

pub(crate) fn validate_pinned_tag(tag: &str) -> Result<(), String> {
    let valid = tag.len() <= 128
        && tag
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && tag
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid || tag == "latest" {
        return Err(format!(
            "llama.cpp release tag must be a safe pinned identifier, not '{tag}'"
        ));
    }
    Ok(())
}

/// Find `name` on `PATH`, returning its full path. This is the
/// preferred acquisition: an operator-installed `llama-server`.
pub fn resolve_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Whether `path` is a regular executable file for the current platform.
pub fn is_executable_file(path: &std::path::Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Ensure a `llama-server` binary is available: prefer one on `PATH`,
/// else download the pinned release for this platform into
/// `cache_dir`, verify its sha256 (when a digest is pinned), extract it,
/// and return the extracted `llama-server` path. Behind the `weights`
/// feature (the download reuses reqwest); shells out to `tar`.
///
/// `expected_sha256` is `Some(hex)` to pin and verify the digest (the
/// WOR-1663 supply-chain posture), or `None` to accept the tagged asset
/// unverified (a warning is logged). A pinned tag is always required;
/// only the digest is optional.
#[cfg(feature = "weights")]
pub async fn ensure_llama_server(
    cache_dir: &std::path::Path,
    tag: &str,
    accel: crate::config::EngineAccel,
    expected_sha256: Option<&str>,
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
    let url = asset_url_accel(tag, platform, accel)?;
    let asset = platform.asset_infix_accel(accel)?;
    let ready_dir = cache_dir.join("llama.cpp").join(tag).join(asset);
    if let Some(binary) = cached_release_binary(&ready_dir, expected_sha256) {
        return Ok(binary);
    }

    let lock_path = cache_dir
        .join("locks")
        .join(format!("llama-release-{tag}-{asset}.lock"));
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let lock = tokio::task::spawn_blocking(move || open_release_lock(&lock_path))
        .await
        .map_err(|e| format!("join llama.cpp release lock: {e}"))??;
    if let Some(binary) = cached_release_binary(&ready_dir, expected_sha256) {
        drop(lock);
        return Ok(binary);
    }

    let staging = cache_dir
        .join("staging")
        .join(format!("llama-release-{tag}-{asset}-{}", ulid::Ulid::new()));
    tokio::fs::create_dir_all(&staging)
        .await
        .map_err(|e| format!("create {}: {e}", staging.display()))?;
    let result = install_release(&url, platform, &staging, &ready_dir, expected_sha256).await;
    let _ = tokio::fs::remove_dir_all(&staging).await;
    drop(lock);
    result
}

#[cfg(feature = "weights")]
async fn install_release(
    url: &str,
    platform: Platform,
    staging: &std::path::Path,
    ready_dir: &std::path::Path,
    expected_sha256: Option<&str>,
) -> Result<PathBuf, String> {
    let archive_path = staging.join(format!("llama.{}", archive_ext(platform)));

    // Download.
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
        .is_some_and(|length| length > MAX_LLAMA_RELEASE_BYTES)
    {
        return Err(format!(
            "llama.cpp release exceeds {MAX_LLAMA_RELEASE_BYTES} bytes"
        ));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("read {url}: {e}"))?;
    if bytes.len() as u64 > MAX_LLAMA_RELEASE_BYTES {
        return Err(format!(
            "llama.cpp release exceeds {MAX_LLAMA_RELEASE_BYTES} bytes"
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
            "llama.cpp release fetched without a pinned sha256; set \
             engines.llama_cpp.acquire.sha256 to verify the download"
        ),
    }

    // Extract. macOS/Linux assets are gzip tarballs (shell out to `tar` to
    // avoid an archive crate dependency in the lean build).
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

    // The binary lands under a bin/ dir in the archive. Check the common
    // layouts first, then fall back to a recursive scan (the layout has
    // shifted across ggml-org releases).
    let binary = [
        staging.join("build/bin/llama-server"),
        staging.join("bin/llama-server"),
        staging.join("llama-server"),
    ]
    .into_iter()
    .find(|candidate| is_executable_file(candidate))
    .or_else(|| find_file_named(staging, "llama-server").filter(|path| is_executable_file(path)))
    .ok_or_else(|| {
        format!(
            "executable llama-server not found in the extracted release under {}",
            staging.display()
        )
    })?;
    let relative_binary = binary
        .strip_prefix(staging)
        .map_err(|e| format!("resolve extracted llama-server path: {e}"))?
        .to_path_buf();
    let marker = expected_sha256.unwrap_or(UNPINNED_RELEASE_MARKER);
    tokio::fs::write(staging.join(".archive.sha256"), marker)
        .await
        .map_err(|e| format!("write llama.cpp release digest marker: {e}"))?;

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
        .map_err(|e| format!("publish llama.cpp release: {e}"))?;
    let published = ready_dir.join(relative_binary);
    if !is_executable_file(&published) {
        return Err(format!(
            "published llama-server is not executable at {}",
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
    find_file_named(ready_dir, "llama-server").filter(|path| is_executable_file(path))
}

#[cfg(feature = "weights")]
fn open_release_lock(path: &std::path::Path) -> Result<std::fs::File, String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| format!("open llama.cpp release lock {}: {e}", path.display()))?;
    file.lock_exclusive()
        .map_err(|e| format!("lock llama.cpp release {}: {e}", path.display()))?;
    Ok(file)
}

/// Recursively search `root` for a file named `name`, returning the first
/// match. Bounded to a small depth: release archives are shallow.
#[cfg(any(feature = "weights", test))]
pub(crate) fn find_file_named(root: &std::path::Path, name: &str) -> Option<PathBuf> {
    fn walk(dir: &std::path::Path, name: &str, depth: usize) -> Option<PathBuf> {
        if depth == 0 {
            return None;
        }
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(hit) = walk(&path, name, depth - 1) {
                    return Some(hit);
                }
            } else if path.file_name().and_then(|n| n.to_str()) == Some(name) {
                return Some(path);
            }
        }
        None
    }
    walk(root, name, 6)
}

/// Blocking wrapper around [`ensure_llama_server`] for synchronous
/// callers. Spins a current-thread runtime for the one download; not
/// for use inside the serving runtime, which is already async.
#[cfg(feature = "weights")]
pub fn ensure_llama_server_blocking(
    cache_dir: &std::path::Path,
    tag: &str,
    accel: crate::config::EngineAccel,
    expected_sha256: Option<&str>,
) -> Result<PathBuf, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?
        .block_on(ensure_llama_server(cache_dir, tag, accel, expected_sha256))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_url_is_pinned_and_platform_specific() {
        // macOS and Linux assets are gzip tarballs.
        assert_eq!(
            asset_url("b9905", Platform::LinuxX64).unwrap(),
            "https://github.com/ggml-org/llama.cpp/releases/download/b9905/llama-b9905-bin-ubuntu-x64.tar.gz"
        );
        assert_eq!(
            asset_url("b9905", Platform::MacOsArm64).unwrap(),
            "https://github.com/ggml-org/llama.cpp/releases/download/b9905/llama-b9905-bin-macos-arm64.tar.gz"
        );
    }

    #[test]
    fn accel_url_uses_vulkan_only_when_vulkan_is_requested() {
        use crate::config::EngineAccel;
        assert_eq!(
            asset_url_accel("b9905", Platform::LinuxX64, EngineAccel::Vulkan).unwrap(),
            "https://github.com/ggml-org/llama.cpp/releases/download/b9905/llama-b9905-bin-ubuntu-vulkan-x64.tar.gz"
        );
        assert_eq!(
            asset_url_accel("b9905", Platform::LinuxX64, EngineAccel::Cpu).unwrap(),
            "https://github.com/ggml-org/llama.cpp/releases/download/b9905/llama-b9905-bin-ubuntu-x64.tar.gz"
        );
        assert!(
            asset_url_accel("b9905", Platform::LinuxX64, EngineAccel::Cuda)
                .unwrap_err()
                .contains("source build")
        );
    }

    #[test]
    fn default_release_assets_have_exact_built_in_digests() {
        use crate::config::EngineAccel;

        assert_eq!(
            default_release_sha256(
                DEFAULT_LLAMA_RELEASE_TAG,
                Platform::MacOsArm64,
                EngineAccel::Metal,
            ),
            Some("0d3deb02fd7912c8ef360fa33b3b4a8c97967a3ac703c0ed7d5edd3680723ea8")
        );
        assert_eq!(
            default_release_sha256(
                DEFAULT_LLAMA_RELEASE_TAG,
                Platform::MacOsX64,
                EngineAccel::Auto,
            ),
            Some("5910cec4ce883d0ddef39974a54a5c9569c4c8b3d13b5e79dfcb32ffda19e44e")
        );
        assert_eq!(
            default_release_sha256(
                DEFAULT_LLAMA_RELEASE_TAG,
                Platform::LinuxX64,
                EngineAccel::Cpu,
            ),
            Some("69f1496c1eda919097668db49e529819e4eda9e8e3d504f90c680fed3587f5b0")
        );
        assert_eq!(
            default_release_sha256(
                DEFAULT_LLAMA_RELEASE_TAG,
                Platform::LinuxX64,
                EngineAccel::Vulkan,
            ),
            Some("81492d7844bcb40c4c025b826dced6b3faa6e484863482d6bd255c84db53bd55")
        );
        assert_eq!(
            default_release_sha256(
                DEFAULT_LLAMA_RELEASE_TAG,
                Platform::LinuxX64,
                EngineAccel::Cuda,
            ),
            None
        );
        assert_eq!(
            default_release_sha256("b-custom", Platform::MacOsArm64, EngineAccel::Metal),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn verified_release_cache_hit_requires_the_matching_digest_marker() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let binary = ready.join("llama-b9905").join("llama-server");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"fixture").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            ready.join(".archive.sha256"),
            DEFAULT_LLAMA_MACOS_ARM64_SHA256,
        )
        .unwrap();

        assert_eq!(
            cached_release_binary(&ready, Some(DEFAULT_LLAMA_MACOS_ARM64_SHA256)),
            Some(binary.clone())
        );
        assert_eq!(
            cached_release_binary(&ready, Some(DEFAULT_LLAMA_MACOS_X64_SHA256)),
            None
        );
        assert_eq!(cached_release_binary(&ready, None), None);
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

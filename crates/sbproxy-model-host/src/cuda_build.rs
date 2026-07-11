// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Atomic, digest-pinned CUDA llama.cpp source builds.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{CommandExecutor, EngineDriverError, EngineFailureReason};

/// Commit referenced by the built-in llama.cpp source tag.
pub const DEFAULT_LLAMA_SOURCE_COMMIT: &str = "024c46ae4e375f20cf51bd7dbaed445f1b02675e";
/// SHA-256 of the official GitHub b9905 source archive.
pub const DEFAULT_LLAMA_SOURCE_SHA256: &str =
    "6324bf83de76623657129265a4fe14fabdf42b93b45d0647af1b8aa723ff08e5";
/// Maximum accepted source archive size.
pub const MAX_LLAMA_SOURCE_BYTES: u64 = 512 * 1024 * 1024;

/// Host tools and hardware required by the fixed CUDA build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CudaBuildPrerequisites {
    /// Whether the host target is Linux x86-64.
    pub linux_x86_64: bool,
    /// Whether an NVIDIA GPU/driver is present.
    pub nvidia_gpu: bool,
    /// CUDA compiler path.
    pub nvcc: Option<PathBuf>,
    /// CMake executable path.
    pub cmake: Option<PathBuf>,
    /// C/C++ compiler path.
    pub compiler: Option<PathBuf>,
    /// Tar executable path.
    pub tar: Option<PathBuf>,
}

impl CudaBuildPrerequisites {
    /// Detect tools from `PATH` and NVIDIA presence from standard host signals.
    pub fn detect_system() -> Self {
        let resolve = crate::llama_release::resolve_on_path;
        Self {
            linux_x86_64: cfg!(all(target_os = "linux", target_arch = "x86_64")),
            nvidia_gpu: Path::new("/proc/driver/nvidia/version").is_file()
                || resolve("nvidia-smi").is_some(),
            nvcc: resolve("nvcc"),
            cmake: resolve("cmake"),
            compiler: resolve("cc")
                .or_else(|| resolve("clang"))
                .or_else(|| resolve("gcc")),
            tar: resolve("tar"),
        }
    }

    /// Whether every fixed build prerequisite is ready.
    pub fn is_ready(&self) -> bool {
        self.validate().is_ok()
    }

    /// Return the first actionable prerequisite failure.
    pub fn validate(&self) -> Result<(), String> {
        if !self.linux_x86_64 {
            return Err("CUDA source builds require Linux x86-64".to_string());
        }
        if !self.nvidia_gpu {
            return Err("CUDA source builds require an NVIDIA GPU and driver".to_string());
        }
        for (name, path) in [
            ("nvcc", self.nvcc.as_ref()),
            ("cmake", self.cmake.as_ref()),
            ("C/C++ compiler", self.compiler.as_ref()),
            ("tar", self.tar.as_ref()),
        ] {
            if path.is_none() {
                return Err(format!("CUDA source build is missing {name}"));
            }
        }
        Ok(())
    }
}

/// Immutable source and cache identity for one CUDA build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CudaBuildPlan {
    cache_dir: PathBuf,
    /// Pinned llama.cpp tag.
    pub tag: String,
    /// Exact official source archive URL.
    pub source_url: String,
    /// Expected source archive SHA-256.
    pub source_sha256: String,
}

impl CudaBuildPlan {
    /// Construct and validate one immutable source build plan.
    pub fn new(
        cache_dir: impl Into<PathBuf>,
        tag: impl Into<String>,
        source_url: impl Into<String>,
        source_sha256: impl Into<String>,
    ) -> Result<Self, EngineDriverError> {
        let plan = Self {
            cache_dir: cache_dir.into(),
            tag: tag.into(),
            source_url: source_url.into(),
            source_sha256: source_sha256.into(),
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Construct a plan for the official tag archive.
    pub fn official(
        cache_dir: impl Into<PathBuf>,
        tag: &str,
        source_sha256: &str,
    ) -> Result<Self, EngineDriverError> {
        Self::new(
            cache_dir,
            tag,
            format!("https://github.com/ggml-org/llama.cpp/archive/refs/tags/{tag}.tar.gz"),
            source_sha256,
        )
    }

    /// Atomically published CUDA `llama-server` path.
    pub fn ready_binary(&self) -> PathBuf {
        self.cache_dir
            .join("llama.cpp")
            .join(&self.tag)
            .join("cuda")
            .join("llama-server")
    }

    fn lock_path(&self) -> PathBuf {
        self.cache_dir
            .join("locks")
            .join(format!("llama-cuda-{}.lock", self.tag))
    }

    fn validate(&self) -> Result<(), EngineDriverError> {
        if self.cache_dir.as_os_str().is_empty() {
            return Err(build_error(
                "CUDA build requires a cache directory and pinned source tag",
                false,
            ));
        }
        crate::llama_release::validate_pinned_tag(&self.tag)
            .map_err(|reason| build_error(reason, false))?;
        let expected_url = format!(
            "https://github.com/ggml-org/llama.cpp/archive/refs/tags/{}.tar.gz",
            self.tag
        );
        if self.source_url != expected_url {
            return Err(build_error(
                "CUDA source URL must be the official tag archive",
                false,
            ));
        }
        if !valid_sha256(&self.source_sha256) {
            return Err(build_error(
                "CUDA source archive requires a 64-character SHA-256",
                false,
            ));
        }
        Ok(())
    }
}

/// Bounded source archive fetch boundary.
#[async_trait]
pub trait CudaSourceFetcher: Send + Sync {
    /// Fetch `url`, refusing a response larger than `max_bytes`.
    async fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, String>;
}

/// Production HTTPS source fetcher.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpCudaSourceFetcher;

#[async_trait]
impl CudaSourceFetcher for HttpCudaSourceFetcher {
    async fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
        #[cfg(feature = "weights")]
        {
            let response = reqwest::Client::new()
                .get(url)
                .send()
                .await
                .map_err(|error| format!("download CUDA source: {error}"))?
                .error_for_status()
                .map_err(|error| format!("download CUDA source: {error}"))?;
            if response
                .content_length()
                .is_some_and(|length| length > max_bytes)
            {
                return Err(format!("CUDA source exceeds {max_bytes} bytes"));
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|error| format!("read CUDA source: {error}"))?;
            if bytes.len() as u64 > max_bytes {
                return Err(format!("CUDA source exceeds {max_bytes} bytes"));
            }
            Ok(bytes.to_vec())
        }
        #[cfg(not(feature = "weights"))]
        {
            let _ = (url, max_bytes);
            Err("CUDA source acquisition requires the model-host weights feature".to_string())
        }
    }
}

/// Locked, atomic CUDA llama.cpp builder.
#[derive(Clone)]
pub struct CudaLlamaBuilder {
    fetcher: Arc<dyn CudaSourceFetcher>,
    executor: Arc<dyn CommandExecutor>,
}

impl std::fmt::Debug for CudaLlamaBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CudaLlamaBuilder")
            .finish_non_exhaustive()
    }
}

impl CudaLlamaBuilder {
    /// Construct a builder with explicit fetch and command boundaries.
    pub fn new(fetcher: Arc<dyn CudaSourceFetcher>, executor: Arc<dyn CommandExecutor>) -> Self {
        Self { fetcher, executor }
    }

    /// Return a verified cache hit or perform one locked atomic build.
    pub async fn build(
        &self,
        plan: &CudaBuildPlan,
        prerequisites: &CudaBuildPrerequisites,
    ) -> Result<PathBuf, EngineDriverError> {
        plan.validate()?;
        prerequisites
            .validate()
            .map_err(|reason| build_error(reason, false))?;
        if crate::llama_release::is_executable_file(&plan.ready_binary()) {
            return Ok(plan.ready_binary());
        }
        let lock_path = plan.lock_path();
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                build_error(format!("create CUDA build lock directory: {error}"), true)
            })?;
        }
        let lock = tokio::task::spawn_blocking(move || open_locked(&lock_path))
            .await
            .map_err(|error| build_error(format!("join CUDA build lock: {error}"), true))??;
        if crate::llama_release::is_executable_file(&plan.ready_binary()) {
            drop(lock);
            return Ok(plan.ready_binary());
        }

        let staging =
            plan.cache_dir
                .join("staging")
                .join(format!("llama-cuda-{}-{}", plan.tag, Ulid::new()));
        fs::create_dir_all(&staging)
            .map_err(|error| build_error(format!("create CUDA build staging: {error}"), true))?;
        let result = self.build_locked(plan, prerequisites, &staging).await;
        let _ = fs::remove_dir_all(&staging);
        drop(lock);
        result
    }

    async fn build_locked(
        &self,
        plan: &CudaBuildPlan,
        prerequisites: &CudaBuildPrerequisites,
        staging: &Path,
    ) -> Result<PathBuf, EngineDriverError> {
        let bytes = self
            .fetcher
            .fetch(&plan.source_url, MAX_LLAMA_SOURCE_BYTES)
            .await
            .map_err(|error| build_error(format!("fetch CUDA source: {error}"), true))?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != plan.source_sha256 {
            return Err(build_error(
                format!(
                    "CUDA source digest mismatch: expected {}, got {actual}",
                    plan.source_sha256
                ),
                false,
            ));
        }
        let archive = staging.join("source.tar.gz");
        fs::write(&archive, bytes)
            .map_err(|error| build_error(format!("write CUDA source: {error}"), true))?;
        let source_parent = staging.join("source");
        fs::create_dir_all(&source_parent)
            .map_err(|error| build_error(format!("create CUDA source directory: {error}"), true))?;
        run_checked(
            self.executor.as_ref(),
            prerequisites.tar.as_deref().expect("validated tar"),
            &[
                "-xzf".to_string(),
                archive.display().to_string(),
                "-C".to_string(),
                source_parent.display().to_string(),
            ],
            Duration::from_secs(120),
            "extract CUDA source",
        )
        .await?;
        let source = source_parent.join(format!("llama.cpp-{}", plan.tag));
        if !source.join("CMakeLists.txt").is_file() {
            return Err(build_error(
                "CUDA source archive did not contain the pinned project root",
                false,
            ));
        }
        let build = staging.join("build");
        run_checked(
            self.executor.as_ref(),
            prerequisites.cmake.as_deref().expect("validated cmake"),
            &[
                "-S".to_string(),
                source.display().to_string(),
                "-B".to_string(),
                build.display().to_string(),
                "-DGGML_CUDA=ON".to_string(),
                "-DGGML_NATIVE=OFF".to_string(),
                "-DLLAMA_CURL=OFF".to_string(),
                "-DCMAKE_BUILD_TYPE=Release".to_string(),
            ],
            Duration::from_secs(300),
            "configure CUDA llama.cpp",
        )
        .await?;
        run_checked(
            self.executor.as_ref(),
            prerequisites.cmake.as_deref().expect("validated cmake"),
            &[
                "--build".to_string(),
                build.display().to_string(),
                "--config".to_string(),
                "Release".to_string(),
                "--target".to_string(),
                "llama-server".to_string(),
                "--parallel".to_string(),
            ],
            Duration::from_secs(3600),
            "build CUDA llama-server",
        )
        .await?;
        let built = build.join("bin/llama-server");
        if !crate::llama_release::is_executable_file(&built) {
            return Err(build_error(
                "CUDA build completed without an executable llama-server",
                false,
            ));
        }
        let ready = plan.ready_binary();
        let parent = ready.parent().expect("ready path has parent");
        fs::create_dir_all(parent)
            .map_err(|error| build_error(format!("create CUDA ready directory: {error}"), true))?;
        fs::rename(&built, &ready)
            .map_err(|error| build_error(format!("publish CUDA llama-server: {error}"), true))?;
        if !crate::llama_release::is_executable_file(&ready) {
            let _ = fs::remove_file(&ready);
            return Err(build_error(
                "published CUDA llama-server is not executable",
                false,
            ));
        }
        Ok(ready)
    }
}

impl Default for CudaLlamaBuilder {
    fn default() -> Self {
        Self::new(
            Arc::new(HttpCudaSourceFetcher),
            Arc::new(crate::TokioCommandExecutor),
        )
    }
}

async fn run_checked(
    executor: &dyn CommandExecutor,
    executable: &Path,
    arguments: &[String],
    timeout: Duration,
    operation: &str,
) -> Result<(), EngineDriverError> {
    let output = executor
        .output(executable, arguments, &BTreeMap::new(), timeout, 64 * 1024)
        .await?;
    if output.success {
        Ok(())
    } else {
        Err(build_error(
            format!("{operation} failed: {}", output.stderr),
            true,
        ))
    }
}

fn open_locked(path: &Path) -> Result<File, EngineDriverError> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|error| build_error(format!("open CUDA build lock: {error}"), true))?;
    file.lock_exclusive()
        .map_err(|error| build_error(format!("lock CUDA build: {error}"), true))?;
    Ok(file)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn build_error(message: impl Into<String>, retryable: bool) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineProvisionFailed,
        message,
        "install the CUDA build prerequisites, verify the source pin, and retry provisioning",
        retryable,
    )
}

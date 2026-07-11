use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sbproxy_model_host::{
    plan_binary_acquire_with_cuda, AcquireSource, BinaryAcquirePlan, CommandExecutor,
    CommandOutput, CudaBuildPlan, CudaBuildPrerequisites, CudaLlamaBuilder, CudaSourceFetcher,
    EngineAccel, EngineAcquire, EngineDriverError, EngineKind, EngineProcess, EngineProvisioning,
    DEFAULT_LLAMA_RELEASE_TAG, DEFAULT_LLAMA_SOURCE_COMMIT, DEFAULT_LLAMA_SOURCE_SHA256,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn complete_prerequisites() -> CudaBuildPrerequisites {
    CudaBuildPrerequisites {
        linux_x86_64: true,
        nvidia_gpu: true,
        nvcc: Some(PathBuf::from("/usr/local/cuda/bin/nvcc")),
        cmake: Some(PathBuf::from("/usr/bin/cmake")),
        compiler: Some(PathBuf::from("/usr/bin/cc")),
        tar: Some(PathBuf::from("/usr/bin/tar")),
    }
}

fn provisioning(acceleration: EngineAccel) -> EngineProvisioning {
    EngineProvisioning {
        acquire: Some(EngineAcquire {
            source: AcquireSource::Release,
            version: Some(DEFAULT_LLAMA_RELEASE_TAG.to_string()),
            accel: acceleration,
            sha256: Some(DEFAULT_LLAMA_SOURCE_SHA256.to_string()),
            path: None,
        }),
        ..EngineProvisioning::default()
    }
}

#[test]
fn cuda_plan_requires_linux_nvidia_toolchain_and_keeps_cpu_vulkan_explicit() {
    assert_eq!(DEFAULT_LLAMA_SOURCE_COMMIT.len(), 40);
    assert_eq!(DEFAULT_LLAMA_SOURCE_SHA256.len(), 64);

    let complete = complete_prerequisites();
    assert!(matches!(
        plan_binary_acquire_with_cuda(
            EngineKind::LlamaCpp,
            Some(&provisioning(EngineAccel::Cuda)),
            None,
            Some(&complete),
        ),
        BinaryAcquirePlan::BuildCuda { ref tag, ref source_sha256 }
            if tag == DEFAULT_LLAMA_RELEASE_TAG && source_sha256 == DEFAULT_LLAMA_SOURCE_SHA256
    ));
    assert!(matches!(
        plan_binary_acquire_with_cuda(
            EngineKind::LlamaCpp,
            Some(&provisioning(EngineAccel::Cuda)),
            Some(PathBuf::from("/usr/bin/llama-server")),
            Some(&complete),
        ),
        BinaryAcquirePlan::BuildCuda { .. }
    ));

    let mut missing_nvcc = complete.clone();
    missing_nvcc.nvcc = None;
    let blocked = plan_binary_acquire_with_cuda(
        EngineKind::LlamaCpp,
        Some(&provisioning(EngineAccel::Cuda)),
        None,
        Some(&missing_nvcc),
    );
    assert!(matches!(blocked, BinaryAcquirePlan::Blocked(ref reason) if reason.contains("nvcc")));

    let auto = provisioning(EngineAccel::Auto);
    assert!(matches!(
        plan_binary_acquire_with_cuda(EngineKind::LlamaCpp, Some(&auto), None, Some(&complete),),
        BinaryAcquirePlan::BuildCuda { .. }
    ));
    assert!(matches!(
        plan_binary_acquire_with_cuda(EngineKind::LlamaCpp, Some(&auto), None, Some(&missing_nvcc),),
        BinaryAcquirePlan::FetchRelease {
            accel: EngineAccel::Auto,
            ..
        }
    ));

    let mut non_nvidia = complete.clone();
    non_nvidia.nvidia_gpu = false;
    assert!(matches!(
        plan_binary_acquire_with_cuda(
            EngineKind::LlamaCpp,
            Some(&provisioning(EngineAccel::Cuda)),
            None,
            Some(&non_nvidia),
        ),
        BinaryAcquirePlan::Blocked(ref reason) if reason.contains("NVIDIA")
    ));

    for acceleration in [EngineAccel::Cpu, EngineAccel::Vulkan] {
        assert!(matches!(
            plan_binary_acquire_with_cuda(
                EngineKind::LlamaCpp,
                Some(&provisioning(acceleration)),
                None,
                Some(&complete),
            ),
            BinaryAcquirePlan::FetchRelease { accel, .. } if accel == acceleration
        ));
    }
}

#[test]
fn cuda_source_identity_rejects_unsafe_or_unpinned_tags() {
    let directory = tempdir().unwrap();
    for tag in ["latest", "../escape", ".hidden", "b9905?archive=other"] {
        assert!(
            CudaBuildPlan::official(directory.path(), tag, DEFAULT_LLAMA_SOURCE_SHA256,).is_err(),
            "{tag}"
        );
    }
}

#[derive(Clone)]
struct FixtureFetcher {
    bytes: Arc<Vec<u8>>,
    fetches: Arc<AtomicUsize>,
}

#[async_trait]
impl CudaSourceFetcher for FixtureFetcher {
    async fn fetch(&self, _url: &str, _max_bytes: u64) -> Result<Vec<u8>, String> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        Ok((*self.bytes).clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildBehavior {
    Success,
    ConfigureFailure,
    BuildFailure,
    MissingOutput,
}

type CapturedCommand = (PathBuf, Vec<String>);
type CapturedCommands = Arc<Mutex<Vec<CapturedCommand>>>;
type FixtureBuilder = (
    CudaLlamaBuilder,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    CapturedCommands,
);

#[derive(Clone)]
struct FixtureExecutor {
    behavior: BuildBehavior,
    commands: CapturedCommands,
    builds: Arc<AtomicUsize>,
}

#[async_trait]
impl CommandExecutor for FixtureExecutor {
    async fn spawn(
        &self,
        _executable: &Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        Err(EngineDriverError::blocked(
            "fixture does not spawn",
            "use bounded output commands",
        ))
    }

    async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _timeout: Duration,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        self.commands
            .lock()
            .unwrap()
            .push((executable.to_path_buf(), arguments.to_vec()));

        let name = executable.file_name().and_then(|value| value.to_str());
        if name == Some("tar") {
            let destination = argument_after(arguments, "-C");
            let source =
                PathBuf::from(destination).join(format!("llama.cpp-{}", DEFAULT_LLAMA_RELEASE_TAG));
            std::fs::create_dir_all(&source).unwrap();
            std::fs::write(source.join("CMakeLists.txt"), b"fixture").unwrap();
            return Ok(success());
        }
        if name == Some("cmake") && arguments.first().map(String::as_str) == Some("-S") {
            return Ok(if self.behavior == BuildBehavior::ConfigureFailure {
                failure("fixture configure failure")
            } else {
                success()
            });
        }
        if name == Some("cmake") && arguments.first().map(String::as_str) == Some("--build") {
            self.builds.fetch_add(1, Ordering::SeqCst);
            if self.behavior == BuildBehavior::BuildFailure {
                return Ok(failure("fixture build failure"));
            }
            if self.behavior != BuildBehavior::MissingOutput {
                let build = PathBuf::from(&arguments[1]);
                let binary = build.join("bin/llama-server");
                std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
                std::fs::write(&binary, b"fixture executable").unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
            }
            return Ok(success());
        }
        Ok(failure("unexpected fixture command"))
    }
}

fn argument_after<'a>(arguments: &'a [String], flag: &str) -> &'a str {
    let index = arguments
        .iter()
        .position(|argument| argument == flag)
        .unwrap_or_else(|| panic!("missing {flag}"));
    &arguments[index + 1]
}

fn success() -> CommandOutput {
    CommandOutput {
        success: true,
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn failure(reason: &str) -> CommandOutput {
    CommandOutput {
        success: false,
        stdout: String::new(),
        stderr: reason.to_string(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fixture_builder(behavior: BuildBehavior, bytes: Vec<u8>) -> FixtureBuilder {
    let fetches = Arc::new(AtomicUsize::new(0));
    let builds = Arc::new(AtomicUsize::new(0));
    let commands = Arc::new(Mutex::new(Vec::new()));
    (
        CudaLlamaBuilder::new(
            Arc::new(FixtureFetcher {
                bytes: Arc::new(bytes),
                fetches: fetches.clone(),
            }),
            Arc::new(FixtureExecutor {
                behavior,
                commands: commands.clone(),
                builds: builds.clone(),
            }),
        ),
        fetches,
        builds,
        commands,
    )
}

#[tokio::test]
async fn concurrent_cuda_builders_share_one_lock_and_publish_only_an_executable() {
    let directory = tempdir().unwrap();
    let bytes = b"fixture source archive".to_vec();
    let plan = CudaBuildPlan::new(
        directory.path(),
        DEFAULT_LLAMA_RELEASE_TAG,
        "https://github.com/ggml-org/llama.cpp/archive/refs/tags/b9905.tar.gz",
        sha256(&bytes),
    )
    .unwrap();
    let (builder, fetches, builds, commands) = fixture_builder(BuildBehavior::Success, bytes);
    let builder = Arc::new(builder);

    let first_prerequisites = complete_prerequisites();
    let second_prerequisites = complete_prerequisites();
    let (first, second) = tokio::join!(
        builder.build(&plan, &first_prerequisites),
        builder.build(&plan, &second_prerequisites)
    );
    let first = first.expect("first build");
    let second = second.expect("second cache hit");
    assert_eq!(first, second);
    assert_eq!(first, plan.ready_binary());
    assert!(sbproxy_model_host::is_executable_file(&first));
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    assert_eq!(builds.load(Ordering::SeqCst), 1);

    let commands = commands.lock().unwrap();
    let configure = commands
        .iter()
        .find(|(_, arguments)| arguments.first().map(String::as_str) == Some("-S"))
        .expect("configure command");
    for exact in [
        "-DGGML_CUDA=ON",
        "-DGGML_NATIVE=OFF",
        "-DLLAMA_CURL=OFF",
        "-DCMAKE_BUILD_TYPE=Release",
    ] {
        assert!(configure.1.iter().any(|argument| argument == exact));
    }
    assert!(!configure.1.iter().any(|argument| argument.contains(';')));
}

#[tokio::test]
async fn cuda_build_failures_leave_no_ready_binary() {
    let bytes = b"fixture source archive".to_vec();
    for behavior in [
        BuildBehavior::ConfigureFailure,
        BuildBehavior::BuildFailure,
        BuildBehavior::MissingOutput,
    ] {
        let directory = tempdir().unwrap();
        let plan = CudaBuildPlan::new(
            directory.path(),
            DEFAULT_LLAMA_RELEASE_TAG,
            "https://github.com/ggml-org/llama.cpp/archive/refs/tags/b9905.tar.gz",
            sha256(&bytes),
        )
        .unwrap();
        let (builder, _, _, _) = fixture_builder(behavior, bytes.clone());
        assert!(builder
            .build(&plan, &complete_prerequisites())
            .await
            .is_err());
        assert!(!plan.ready_binary().exists(), "{behavior:?}");
    }

    let directory = tempdir().unwrap();
    let plan = CudaBuildPlan::new(
        directory.path(),
        DEFAULT_LLAMA_RELEASE_TAG,
        "https://github.com/ggml-org/llama.cpp/archive/refs/tags/b9905.tar.gz",
        "0".repeat(64),
    )
    .unwrap();
    let (builder, _, _, _) = fixture_builder(BuildBehavior::Success, bytes);
    assert!(builder
        .build(&plan, &complete_prerequisites())
        .await
        .is_err());
    assert!(!plan.ready_binary().exists(), "digest mismatch");
}

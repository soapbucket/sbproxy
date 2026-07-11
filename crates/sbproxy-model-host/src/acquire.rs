// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Engine acquisition planning (WOR-1801).
//!
//! The launcher used to spawn `engine.binary_name()` from `PATH` and
//! nothing else: a host without the binary failed at the first request.
//! This module decides, from a serve entry's optional `acquire:` block
//! and what is on `PATH`, how to obtain a *binary* engine (llama.cpp):
//! use it from `PATH`, use an operator-provided path, fetch a pinned
//! prebuilt release, or build CUDA from pinned source. The decision is
//! pure and unit-tested; async provisioning is the runtime's job, driven
//! by the [`BinaryAcquirePlan`] this returns.
//!
//! Engine *identity* stays the allowlisted [`EngineKind`]; only the
//! acquisition method is configurable, so the config-spawn security
//! posture (no arbitrary `cmd:`) is unchanged: a plan can name a `PATH`
//! program, an operator's own path, a pinned ggml-org release, or a fixed
//! source-build recipe, never an arbitrary command line.

use std::path::PathBuf;

use crate::config::{AcquireSource, EngineAccel, EngineKind, EngineProvisioning};
use crate::llama_release::{Platform, DEFAULT_LLAMA_RELEASE_TAG};

/// How to obtain a binary engine, decided from config + environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryAcquirePlan {
    /// The binary is already on `PATH` at this resolved path.
    OnPath(PathBuf),
    /// Use the operator-provided explicit path (`acquire.source: path`).
    Explicit(PathBuf),
    /// Fetch the pinned llama.cpp release: tag, accel, and an optional
    /// sha256 to verify against.
    FetchRelease {
        /// The release tag to fetch (never `latest`).
        tag: String,
        /// The acceleration flavour (drives which asset).
        accel: EngineAccel,
        /// Expected sha256 hex, or `None` to fetch unverified (warned).
        sha256: Option<String>,
    },
    /// Build one CUDA-enabled llama.cpp binary from pinned source.
    BuildCuda {
        /// Pinned llama.cpp release tag.
        tag: String,
        /// Expected SHA-256 of the official source archive.
        source_sha256: String,
    },
    /// Provision vLLM via `uvx` (`uv tool run`): fetch the `uv` binary,
    /// then run `uv tool run --from vllm[==version] vllm ...`. uv sets up
    /// and caches the environment (and its own Python) on first use.
    ProvisionUvx {
        /// The vLLM package version to pin (`--from vllm==<v>`), or `None`
        /// for the latest resolvable.
        vllm_version: Option<String>,
    },
    /// The binary cannot be acquired here; the reason is for `plan` /
    /// `doctor`, surfaced before a request rather than at first use.
    Blocked(String),
}

/// Decide how to obtain the binary for `engine`, given its optional
/// provisioning and where (if anywhere) the binary already resolves on
/// `PATH`. Pure: no fetch, no filesystem writes.
///
/// Only binary engines (llama.cpp) are acquired here. vLLM is not a
/// single-binary release (use a container or venv), and the embedded
/// engine runs in-process; both return [`BinaryAcquirePlan::Blocked`]
/// with the reason unless already on `PATH`.
pub fn plan_binary_acquire(
    engine: EngineKind,
    prov: Option<&EngineProvisioning>,
    on_path: Option<PathBuf>,
) -> BinaryAcquirePlan {
    let prerequisites = crate::CudaBuildPrerequisites::detect_system();
    plan_binary_acquire_with_cuda(engine, prov, on_path, Some(&prerequisites))
}

/// Decide binary acquisition with explicit CUDA build prerequisites.
///
/// This deterministic variant lets doctor and tests distinguish an acquirable
/// CUDA source build from a blocked explicit CUDA request. `Auto` chooses the
/// source build only when every prerequisite is ready; otherwise it keeps the
/// ordinary release path.
pub fn plan_binary_acquire_with_cuda(
    engine: EngineKind,
    prov: Option<&EngineProvisioning>,
    on_path: Option<PathBuf>,
    cuda: Option<&crate::CudaBuildPrerequisites>,
) -> BinaryAcquirePlan {
    let acquire = prov.and_then(|p| p.acquire.as_ref());

    // An explicit path override wins over everything, so an air-gapped
    // box can point at a vetted binary.
    if let Some(acq) = acquire {
        if acq.source == AcquireSource::Path {
            return match acq.path.as_deref().filter(|p| !p.trim().is_empty()) {
                Some(path) => BinaryAcquirePlan::Explicit(PathBuf::from(path)),
                None => BinaryAcquirePlan::Blocked(
                    "acquire.source: path needs a non-empty `path`".to_string(),
                ),
            };
        }
    }

    // PATH-first for ordinary release acquisition. An explicit CUDA or
    // source-build request cannot safely reuse an uninspected PATH binary:
    // it may be CPU-only and it does not carry the requested source identity.
    let requires_cuda_source = engine == EngineKind::LlamaCpp
        && acquire.is_some_and(|acquire| {
            acquire.source == AcquireSource::SourceBuild || acquire.accel == EngineAccel::Cuda
        });
    if !requires_cuda_source {
        if let Some(p) = on_path {
            return BinaryAcquirePlan::OnPath(p);
        }
    }

    match engine {
        EngineKind::LlamaCpp => {
            if Platform::detect().is_none() {
                return BinaryAcquirePlan::Blocked(format!(
                    "no prebuilt llama.cpp release for {}/{}; install llama.cpp on PATH \
                     or build from source",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ));
            }
            let tag = acquire
                .and_then(|a| a.version.clone())
                .unwrap_or_else(|| DEFAULT_LLAMA_RELEASE_TAG.to_string());
            let accel = acquire.map(|a| a.accel).unwrap_or_default();
            let configured_sha256 = acquire.and_then(|a| a.sha256.clone());
            let source_build_requested = acquire
                .is_some_and(|acquire| acquire.source == AcquireSource::SourceBuild)
                || accel == EngineAccel::Cuda;
            let auto_cuda_ready = accel == EngineAccel::Auto
                && cuda.is_some_and(crate::CudaBuildPrerequisites::is_ready);
            if source_build_requested || auto_cuda_ready {
                let Some(prerequisites) = cuda else {
                    return BinaryAcquirePlan::Blocked(
                        "CUDA llama.cpp build prerequisites were not detected".to_string(),
                    );
                };
                if let Err(reason) = prerequisites.validate() {
                    if source_build_requested {
                        return BinaryAcquirePlan::Blocked(format!(
                            "CUDA llama.cpp build is blocked: {reason}"
                        ));
                    }
                } else {
                    let source_sha256 = match configured_sha256 {
                        Some(sha256) => sha256,
                        None if tag == DEFAULT_LLAMA_RELEASE_TAG => {
                            crate::DEFAULT_LLAMA_SOURCE_SHA256.to_string()
                        }
                        None => {
                            return BinaryAcquirePlan::Blocked(format!(
                                "CUDA source build for custom tag {tag:?} requires acquire.sha256"
                            ));
                        }
                    };
                    return BinaryAcquirePlan::BuildCuda { tag, source_sha256 };
                }
            }
            let sha256 = configured_sha256.or_else(|| {
                Platform::detect().and_then(|platform| {
                    crate::llama_release::default_release_sha256(&tag, platform, accel)
                        .map(str::to_string)
                })
            });
            BinaryAcquirePlan::FetchRelease { tag, accel, sha256 }
        }
        EngineKind::Vllm => match acquire.map(|a| a.source) {
            // Opt-in `uvx` provisioning: fetch uv and run vLLM through an
            // ephemeral, cached environment (uv brings its own Python).
            // The vLLM package version is the acquire block's `version`.
            Some(AcquireSource::Uvx) => BinaryAcquirePlan::ProvisionUvx {
                vllm_version: acquire.and_then(|a| a.version.clone()),
            },
            // Default: vLLM is not a single-binary release, so without an
            // explicit acquisition method it is not fetched here (it still
            // spawns from PATH if installed). Left Blocked so a default
            // config does not trigger a heavy environment build.
            _ => BinaryAcquirePlan::Blocked(
                "vLLM is not a single-binary release; set engines.vllm.acquire.source: uvx to run \
                 it via `uv tool run`, use a container, or install it on PATH"
                    .to_string(),
            ),
        },
        EngineKind::Embedded => BinaryAcquirePlan::Blocked(
            "the embedded engine runs in-process; there is no binary to acquire".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EngineAcquire;

    #[test]
    fn on_path_wins_for_release_default() {
        let plan = plan_binary_acquire(
            EngineKind::LlamaCpp,
            None,
            Some(PathBuf::from("/usr/bin/llama-server")),
        );
        assert_eq!(
            plan,
            BinaryAcquirePlan::OnPath(PathBuf::from("/usr/bin/llama-server"))
        );
    }

    #[test]
    fn explicit_path_override_wins_even_over_path() {
        let prov = EngineProvisioning {
            acquire: Some(EngineAcquire {
                source: AcquireSource::Path,
                path: Some("/opt/llama/llama-server".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Even with a PATH hit, an explicit path is honoured.
        let plan = plan_binary_acquire(
            EngineKind::LlamaCpp,
            Some(&prov),
            Some(PathBuf::from("/usr/bin/llama-server")),
        );
        assert_eq!(
            plan,
            BinaryAcquirePlan::Explicit(PathBuf::from("/opt/llama/llama-server"))
        );
    }

    #[test]
    fn path_source_without_path_is_blocked() {
        let prov = EngineProvisioning {
            acquire: Some(EngineAcquire {
                source: AcquireSource::Path,
                path: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        match plan_binary_acquire(EngineKind::LlamaCpp, Some(&prov), None) {
            BinaryAcquirePlan::Blocked(r) => assert!(r.contains("needs a non-empty")),
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn release_uses_default_tag_when_unset() {
        // No engine on PATH, default provisioning: fetch the pinned
        // default release and its built-in asset digest for this platform
        // (the test host is a supported platform).
        let plan = plan_binary_acquire(EngineKind::LlamaCpp, None, None);
        match plan {
            BinaryAcquirePlan::FetchRelease { tag, sha256, .. } => {
                assert_eq!(tag, DEFAULT_LLAMA_RELEASE_TAG);
                assert_eq!(sha256.as_deref().map(str::len), Some(64));
            }
            // A platform with no prebuilt asset blocks instead; both are
            // valid depending on the test host.
            BinaryAcquirePlan::Blocked(r) => assert!(r.contains("no prebuilt")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn release_honours_pinned_version_and_sha() {
        let prov = EngineProvisioning {
            acquire: Some(EngineAcquire {
                source: AcquireSource::Release,
                version: Some("b9999".to_string()),
                sha256: Some("abc123".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        match plan_binary_acquire(EngineKind::LlamaCpp, Some(&prov), None) {
            BinaryAcquirePlan::FetchRelease { tag, sha256, .. } => {
                assert_eq!(tag, "b9999");
                assert_eq!(sha256.as_deref(), Some("abc123"));
            }
            BinaryAcquirePlan::Blocked(r) => assert!(r.contains("no prebuilt")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn vllm_and_embedded_have_no_binary_release() {
        // Default vLLM (no acquire block) is not fetched: it stays Blocked
        // so a plain config never triggers a heavy env build.
        assert!(matches!(
            plan_binary_acquire(EngineKind::Vllm, None, None),
            BinaryAcquirePlan::Blocked(_)
        ));
        assert!(matches!(
            plan_binary_acquire(EngineKind::Embedded, None, None),
            BinaryAcquirePlan::Blocked(_)
        ));
        // ...unless vLLM happens to be on PATH.
        assert_eq!(
            plan_binary_acquire(EngineKind::Vllm, None, Some(PathBuf::from("/usr/bin/vllm"))),
            BinaryAcquirePlan::OnPath(PathBuf::from("/usr/bin/vllm"))
        );
    }

    #[test]
    fn vllm_uvx_source_provisions_via_uvx() {
        let prov = EngineProvisioning {
            acquire: Some(EngineAcquire {
                source: AcquireSource::Uvx,
                version: Some("0.6.3".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            plan_binary_acquire(EngineKind::Vllm, Some(&prov), None),
            BinaryAcquirePlan::ProvisionUvx {
                vllm_version: Some("0.6.3".to_string())
            }
        );
    }

    #[test]
    fn vllm_uvx_without_version_is_unpinned() {
        let prov = EngineProvisioning {
            acquire: Some(EngineAcquire {
                source: AcquireSource::Uvx,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            plan_binary_acquire(EngineKind::Vllm, Some(&prov), None),
            BinaryAcquirePlan::ProvisionUvx { vllm_version: None }
        );
    }

    #[test]
    fn vllm_on_path_wins_over_uvx() {
        let prov = EngineProvisioning {
            acquire: Some(EngineAcquire {
                source: AcquireSource::Uvx,
                ..Default::default()
            }),
            ..Default::default()
        };
        // A host vLLM install is preferred over provisioning a new env.
        assert_eq!(
            plan_binary_acquire(
                EngineKind::Vllm,
                Some(&prov),
                Some(PathBuf::from("/usr/bin/vllm"))
            ),
            BinaryAcquirePlan::OnPath(PathBuf::from("/usr/bin/vllm"))
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Engine acquisition planning (WOR-1801).
//!
//! The launcher used to spawn `engine.binary_name()` from `PATH` and
//! nothing else: a host without the binary failed at the first request.
//! This module decides, from a serve entry's optional `acquire:` block
//! and what is on `PATH`, how to obtain a *binary* engine (llama.cpp):
//! use it from `PATH`, use an operator-provided path, or fetch a pinned
//! prebuilt release. The decision is pure and unit-tested; the async
//! fetch (behind the `weights` feature) is the runtime's job, driven by
//! the [`BinaryAcquirePlan`] this returns.
//!
//! Engine *identity* stays the allowlisted [`EngineKind`]; only the
//! acquisition method is configurable, so the config-spawn security
//! posture (no arbitrary `cmd:`) is unchanged: a plan can name a `PATH`
//! program, an operator's own path, or a pinned ggml-org release, never
//! an arbitrary command line.

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

    // PATH-first for the release path: a host-installed binary is
    // preferred over a download.
    if let Some(p) = on_path {
        return BinaryAcquirePlan::OnPath(p);
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
            let sha256 = acquire.and_then(|a| a.sha256.clone());
            BinaryAcquirePlan::FetchRelease { tag, accel, sha256 }
        }
        EngineKind::Vllm => BinaryAcquirePlan::Blocked(
            "vLLM is not a single-binary release; run it from a container (engines.vllm.launch: \
             container) or a managed venv"
                .to_string(),
        ),
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
        // default release for this platform (the test host is a
        // supported platform).
        let plan = plan_binary_acquire(EngineKind::LlamaCpp, None, None);
        match plan {
            BinaryAcquirePlan::FetchRelease { tag, sha256, .. } => {
                assert_eq!(tag, DEFAULT_LLAMA_RELEASE_TAG);
                assert!(sha256.is_none());
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
}

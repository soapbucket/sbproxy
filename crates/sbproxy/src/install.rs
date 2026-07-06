// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! `sbproxy doctor --install <target>`: acquire a missing `serve:`
//! prerequisite with the host's own tooling.
//!
//! Security posture, aligned with the model-host spawn constraints:
//! every executed command is a fixed argv (no shell interpolation),
//! the exact command is printed before anything runs, nothing runs
//! without confirmation (interactive y/N, or `--yes` for provisioning
//! scripts), and the llama.cpp release path is pinned (an explicit
//! tag plus the archive's sha256; `latest` is rejected). GPU drivers
//! are never installed; a missing driver gets printed guidance only.

use std::path::{Path, PathBuf};

/// What `--install` can acquire.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallTarget {
    /// vLLM, via `uv tool install vllm` or `pipx install vllm`.
    Vllm,
    /// llama.cpp's `llama-server`, via Homebrew or a pinned GitHub
    /// release (`--llama-tag` + `--llama-sha256`).
    LlamaCpp,
}

/// Which installer tooling this host offers. Probed once per run.
#[derive(Debug, Clone, Copy)]
struct Tooling {
    uv: bool,
    pipx: bool,
    brew: bool,
}

impl Tooling {
    fn probe() -> Self {
        let has = |p: &str| sbproxy_model_host::resolve_on_path(p).is_some();
        Self {
            uv: has("uv"),
            pipx: has("pipx"),
            brew: has("brew"),
        }
    }
}

/// The resolved installation strategy for a target on this host.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Execute this fixed argv.
    Run(Vec<&'static str>),
    /// Download the pinned llama.cpp release and link `llama-server`
    /// into the bin dir.
    LlamaRelease { tag: String, sha256: String },
    /// Nothing safe to execute; print this and exit nonzero.
    Guidance(String),
}

/// Pick the strategy: package manager first (it owns upgrades and
/// PATH), pinned release second, copy-paste guidance last.
fn plan(
    target: InstallTarget,
    tooling: &Tooling,
    llama_tag: Option<&str>,
    llama_sha256: Option<&str>,
) -> Plan {
    match target {
        InstallTarget::Vllm => {
            if tooling.uv {
                Plan::Run(vec!["uv", "tool", "install", "vllm"])
            } else if tooling.pipx {
                Plan::Run(vec!["pipx", "install", "vllm"])
            } else {
                Plan::Guidance(
                    "no supported Python tool installer found (looked for uv, pipx).\n\
                     Install one and re-run:\n\
                     - uv:   https://docs.astral.sh/uv/getting-started/installation/\n\
                     - pipx: https://pipx.pypa.io/stable/installation/\n\
                     Or skip the PATH binary entirely and run vLLM from a pinned\n\
                     container image with docker/podman via the serve: block's\n\
                     engines: { vllm: { launch: container, image: <pinned> } }."
                        .to_string(),
                )
            }
        }
        InstallTarget::LlamaCpp => {
            if tooling.brew {
                Plan::Run(vec!["brew", "install", "llama.cpp"])
            } else if let (Some(tag), Some(sha)) = (llama_tag, llama_sha256) {
                Plan::LlamaRelease {
                    tag: tag.to_string(),
                    sha256: sha.to_string(),
                }
            } else {
                Plan::Guidance(
                    "no Homebrew found. Either install Homebrew (macOS/Linux) and\n\
                     re-run, or install a pinned upstream release:\n\
                     sbproxy doctor --install llama-cpp \\\n\
                       --llama-tag <release-tag> --llama-sha256 <sha256-of-the-zip>\n\
                     Releases and their checksums: \
                     https://github.com/ggml-org/llama.cpp/releases"
                        .to_string(),
                )
            }
        }
    }
}

/// Run the `--install` flow. Returns the process exit code: 0 when the
/// prerequisite is in place afterwards, 1 when it is not (guidance
/// printed, declined confirmation, or a failed install).
pub fn run(
    target: InstallTarget,
    yes: bool,
    llama_tag: Option<&str>,
    llama_sha256: Option<&str>,
    bin_dir: &Path,
) -> anyhow::Result<i32> {
    let tooling = Tooling::probe();
    match plan(target, &tooling, llama_tag, llama_sha256) {
        Plan::Guidance(text) => {
            eprintln!("doctor --install: cannot install automatically on this host.\n{text}");
            Ok(1)
        }
        Plan::Run(argv) => {
            println!("will run: {}", argv.join(" "));
            if !yes && !confirm()? {
                println!("aborted; nothing was run");
                return Ok(1);
            }
            let status = std::process::Command::new(argv[0])
                .args(&argv[1..])
                .status()
                .map_err(|e| anyhow::anyhow!("failed to run {}: {e}", argv[0]))?;
            if !status.success() {
                eprintln!("doctor --install: `{}` failed ({status})", argv.join(" "));
                return Ok(1);
            }
            report_after_install();
            Ok(0)
        }
        Plan::LlamaRelease { tag, sha256 } => install_llama_release(&tag, &sha256, yes, bin_dir),
    }
}

/// Download the pinned llama.cpp release into the model cache, verify
/// its sha256, extract it, and link `llama-server` into `bin_dir` so
/// the engine launcher (which resolves from PATH) can find it.
#[cfg(feature = "model-weights")]
fn install_llama_release(
    tag: &str,
    sha256: &str,
    yes: bool,
    bin_dir: &Path,
) -> anyhow::Result<i32> {
    let cache_dir = sbproxy_model_host::resolve_cache_dir(None, None);
    let platform = sbproxy_model_host::Platform::detect().ok_or_else(|| {
        anyhow::anyhow!(
            "no prebuilt llama.cpp release for {}/{}; build from source or use Homebrew",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let url = sbproxy_model_host::llama_asset_url(tag, platform).map_err(anyhow::Error::msg)?;
    println!(
        "will download {url}\n  verify sha256 {sha256}\n  extract under {}\n  link llama-server into {}",
        cache_dir.display(),
        bin_dir.display()
    );
    if !yes && !confirm()? {
        println!("aborted; nothing was downloaded");
        return Ok(1);
    }
    let extracted = sbproxy_model_host::ensure_llama_server_blocking(&cache_dir, tag, sha256)
        .map_err(anyhow::Error::msg)?;
    match link_into_bin_dir(&extracted, bin_dir) {
        Ok(linked) => {
            println!("installed: {}", linked.display());
            report_after_install();
            Ok(0)
        }
        Err(e) => {
            eprintln!(
                "downloaded and verified {} but could not link it into {}: {e}\n\
                 Copy it onto PATH yourself, e.g.:\n  sudo cp {} {}/llama-server",
                extracted.display(),
                bin_dir.display(),
                extracted.display(),
                bin_dir.display()
            );
            Ok(1)
        }
    }
}

/// A build without the weight-download feature cannot fetch releases.
#[cfg(not(feature = "model-weights"))]
fn install_llama_release(
    _tag: &str,
    _sha256: &str,
    _yes: bool,
    _bin_dir: &Path,
) -> anyhow::Result<i32> {
    eprintln!(
        "doctor --install: this build lacks the model-weights feature, so it \
         cannot download releases; rebuild with --features model-weights or \
         install llama.cpp with Homebrew"
    );
    Ok(1)
}

/// Symlink (or copy, when symlinking fails) the extracted binary into
/// the bin dir.
#[cfg(feature = "model-weights")]
fn link_into_bin_dir(extracted: &Path, bin_dir: &Path) -> std::io::Result<PathBuf> {
    let dest = bin_dir.join("llama-server");
    if dest.exists() {
        std::fs::remove_file(&dest)?;
    }
    #[cfg(unix)]
    {
        if std::os::unix::fs::symlink(extracted, &dest).is_ok() {
            return Ok(dest);
        }
    }
    std::fs::copy(extracted, &dest)?;
    Ok(dest)
}

/// Re-probe the host and print the doctor report, so the operator sees
/// the post-install verdict without a second command.
fn report_after_install() {
    println!();
    print!(
        "{}",
        sbproxy_core::doctor::DoctorReport::collect().render_text()
    );
}

/// Interactive y/N prompt on stdin. Anything but an explicit yes is no.
fn confirm() -> anyhow::Result<bool> {
    use std::io::Write as _;
    print!("proceed? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_TOOLS: Tooling = Tooling {
        uv: false,
        pipx: false,
        brew: false,
    };

    #[test]
    fn vllm_prefers_uv_over_pipx() {
        let both = Tooling {
            uv: true,
            pipx: true,
            brew: false,
        };
        assert_eq!(
            plan(InstallTarget::Vllm, &both, None, None),
            Plan::Run(vec!["uv", "tool", "install", "vllm"])
        );
        let pipx_only = Tooling {
            uv: false,
            pipx: true,
            brew: false,
        };
        assert_eq!(
            plan(InstallTarget::Vllm, &pipx_only, None, None),
            Plan::Run(vec!["pipx", "install", "vllm"])
        );
    }

    #[test]
    fn vllm_without_tooling_is_guidance_not_a_command() {
        match plan(InstallTarget::Vllm, &NO_TOOLS, None, None) {
            Plan::Guidance(g) => {
                assert!(g.contains("uv"));
                assert!(g.contains("container"), "offers the container path");
            }
            other => panic!("expected guidance, got {other:?}"),
        }
    }

    #[test]
    fn llama_prefers_brew_then_pinned_release() {
        let brew = Tooling {
            uv: false,
            pipx: false,
            brew: true,
        };
        assert_eq!(
            plan(InstallTarget::LlamaCpp, &brew, None, None),
            Plan::Run(vec!["brew", "install", "llama.cpp"])
        );
        assert_eq!(
            plan(
                InstallTarget::LlamaCpp,
                &NO_TOOLS,
                Some("b4589"),
                Some("abc123")
            ),
            Plan::LlamaRelease {
                tag: "b4589".to_string(),
                sha256: "abc123".to_string(),
            }
        );
    }

    #[test]
    fn llama_release_needs_both_tag_and_sha() {
        // A tag without its digest must not silently download; the
        // pinned posture requires both.
        for (tag, sha) in [(Some("b4589"), None), (None, Some("abc")), (None, None)] {
            match plan(InstallTarget::LlamaCpp, &NO_TOOLS, tag, sha) {
                Plan::Guidance(g) => assert!(g.contains("--llama-sha256")),
                other => panic!("expected guidance for {tag:?}/{sha:?}, got {other:?}"),
            }
        }
    }
}

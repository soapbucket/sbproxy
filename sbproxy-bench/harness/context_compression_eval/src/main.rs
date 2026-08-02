use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use context_compression_eval::{
    adapt_external_jsonl, build_stateless_levers, evaluate_cases, load_provenance, parse_cases,
    render_json, render_markdown, verify_fixture_set, EvalConfig, EvalPipelineFile, EvalReport,
    ExternalSuite, FixtureArtifact, Recommendation, VerifiedProvenanceSummary,
};

#[derive(Debug, Parser)]
#[command(
    name = "context-compression-eval",
    about = "Run deterministic off/on context-compression evaluations"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Regenerate JSON and Markdown evaluation reports.
    Generate {
        #[command(flatten)]
        reports: ReportArgs,
        /// Capture observed wall-clock latency in a non-gated report.
        #[arg(long)]
        measure_latency: bool,
    },
    /// Fail unless committed reports match deterministic regeneration.
    Check {
        #[command(flatten)]
        reports: ReportArgs,
    },
    /// Convert documented external interchange JSONL to normalized JSONL.
    Adapt {
        /// External suite that produced the operator-supplied rows.
        #[arg(long, value_enum)]
        suite: ExternalSuite,
        /// External interchange JSONL input.
        #[arg(long)]
        input: PathBuf,
        /// Normalized JSONL output.
        #[arg(long)]
        output: PathBuf,
        /// Target model used when the normalized cases are evaluated.
        #[arg(long)]
        target_model: String,
    },
}

#[derive(Debug, Clone, Args)]
struct ReportArgs {
    /// Checked ordered compression pipeline configuration.
    #[arg(long)]
    pipeline_config: PathBuf,
    /// Normalized JSONL input. Repeat for multiple corpora.
    #[arg(long, required = true)]
    input: Vec<PathBuf>,
    /// Provenance and checksum manifest covering every input.
    #[arg(long)]
    provenance: PathBuf,
    /// Root against which provenance paths are resolved.
    #[arg(long, default_value = ".")]
    harness_root: PathBuf,
    /// JSON report path.
    #[arg(long)]
    json_report: PathBuf,
    /// Markdown report path.
    #[arg(long)]
    markdown_report: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate {
            reports,
            measure_latency,
        } => {
            let (_, json, markdown) = generate(&reports, measure_latency).await?;
            write_file(&reports.json_report, &json)?;
            write_file(&reports.markdown_report, &markdown)?;
        }
        Command::Check { reports } => {
            let (report, json, markdown) = generate(&reports, false).await?;
            if report.overall.recommendation != Recommendation::Build {
                bail!(
                    "overall recommendation is {}, expected build",
                    recommendation_label(report.overall.recommendation)
                );
            }
            check_file(&reports.json_report, &json, "JSON")?;
            check_file(&reports.markdown_report, &markdown, "Markdown")?;
        }
        Command::Adapt {
            suite,
            input,
            output,
            target_model,
        } => {
            let bytes = fs::read(&input)
                .with_context(|| format!("read external input {}", input.display()))?;
            let normalized = adapt_external_jsonl(bytes.as_slice(), suite, &target_model)?;
            write_file(&output, &normalized)?;
        }
    }
    Ok(())
}

async fn generate(
    args: &ReportArgs,
    measure_latency: bool,
) -> Result<(EvalReport, String, String)> {
    let pipeline = load_pipeline(&args.pipeline_config)?;
    let provenance_bytes = fs::read(&args.provenance)
        .with_context(|| format!("read provenance {}", args.provenance.display()))?;
    let provenance = load_provenance(provenance_bytes.as_slice())?;
    verify_fixture_set(&args.harness_root, &provenance)?;
    let selected_artifacts = verify_inputs_covered(args, &provenance)?;

    let mut cases = Vec::new();
    let mut ids = BTreeSet::new();
    for path in &args.input {
        let bytes = fs::read(path).with_context(|| format!("read input {}", path.display()))?;
        for case in parse_cases(bytes.as_slice())? {
            if !ids.insert(case.id.clone()) {
                bail!("duplicate case id `{}` across inputs", case.id);
            }
            cases.push(case);
        }
    }
    let mut report = evaluate_cases(
        &cases,
        &EvalConfig {
            profile: pipeline.profile,
            levers: pipeline.levers,
            measure_latency,
        },
    )
    .await?;
    report.verified_provenance = Some(VerifiedProvenanceSummary::from_verified_inputs(
        &provenance_bytes,
        selected_artifacts,
    ));
    let json = render_json(&report)?;
    let markdown = render_markdown(&report);
    Ok((report, json, markdown))
}

fn load_pipeline(path: &Path) -> Result<EvalPipelineFile> {
    let bytes =
        fs::read(path).with_context(|| format!("read pipeline config {}", path.display()))?;
    let pipeline: EvalPipelineFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse pipeline config {}", path.display()))?;
    if pipeline.schema_version != 1 {
        bail!(
            "unsupported pipeline schema version {}",
            pipeline.schema_version
        );
    }
    if pipeline.profile.trim().is_empty() {
        bail!("pipeline profile must not be empty");
    }
    build_stateless_levers(&pipeline.levers)?;
    Ok(pipeline)
}

fn recommendation_label(recommendation: Recommendation) -> &'static str {
    match recommendation {
        Recommendation::Build => "build",
        Recommendation::Borrow => "borrow",
        Recommendation::Defer => "defer",
    }
}

fn verify_inputs_covered(
    args: &ReportArgs,
    manifest: &context_compression_eval::ProvenanceManifest,
) -> Result<Vec<FixtureArtifact>> {
    let covered = manifest
        .artifacts
        .iter()
        .map(|artifact| {
            let path = args.harness_root.join(&artifact.path);
            let resolved = fs::canonicalize(&path)
                .with_context(|| format!("resolve covered input {}", path.display()))?;
            Ok((resolved, artifact))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut selected = Vec::with_capacity(args.input.len());
    for input in &args.input {
        let resolved = fs::canonicalize(input)
            .with_context(|| format!("resolve input {}", input.display()))?;
        let Some((_, artifact)) = covered.iter().find(|(path, _)| path == &resolved) else {
            bail!(
                "input {} is not covered by the provenance manifest",
                input.display()
            );
        };
        selected.push((*artifact).clone());
    }
    selected.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(selected)
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("write output {}", path.display()))
}

fn check_file(path: &Path, expected: &str, label: &str) -> Result<()> {
    let actual = fs::read_to_string(path)
        .with_context(|| format!("read committed {label} report {}", path.display()))?;
    if actual != expected {
        bail!(
            "{label} report drift at {}; run the generate command and review the change",
            path.display()
        );
    }
    Ok(())
}

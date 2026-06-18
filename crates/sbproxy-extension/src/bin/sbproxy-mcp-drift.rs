// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! `sbproxy-mcp-drift`: CI-friendly schema-drift checker for
//! converted MCP servers (WOR-486).
//!
//! Compares two OpenAPI snapshots (or one snapshot against a
//! `last-known` digest) and prints the classified diff. Exit
//! code mirrors the overall severity so a CI gate can `if
//! sbproxy-mcp-drift ... ; then ...` without parsing output:
//!
//! * `0` no drift
//! * `1` informational only
//! * `2` breaking changes
//!
//! ## Usage
//!
//! ```bash
//! sbproxy-mcp-drift --previous prev.json --current cur.json
//! sbproxy-mcp-drift --previous prev.yaml --current cur.yaml --format json
//! sbproxy-mcp-drift --cassette run.ndjson --current-tools tools-list.json
//! ```
//!
//! OpenAPI inputs accept JSON or YAML. Cassette inputs also accept
//! NDJSON session-ledger records.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use sbproxy_extension::mcp::cassette_drift::{
    diff_cassette_values, load_document, CassetteDriftReport,
};
use sbproxy_extension::mcp::schema_drift::{diff_openapi, DriftSeverity};

fn print_usage() {
    eprintln!(
        "sbproxy-mcp-drift: classify OpenAPI changes by severity (WOR-486)\n\
        \n\
        USAGE:\n    \
            sbproxy-mcp-drift --previous <FILE> --current <FILE> [--format text|json]\n    \
            sbproxy-mcp-drift --cassette <FILE> --current-tools <FILE> [--format text|json]\n\
        \n\
        EXIT CODES:\n    \
            0   no drift\n    \
            1   informational changes only (description / optional-added / enum-widened)\n    \
            2   breaking changes (operation removed / required-removed / type-changed / enum-narrowed)\n\
        \n\
        FORMATS:\n    \
            text  (default) human-readable summary grouped by severity\n    \
            json  structured DriftReport suitable for downstream tooling\n\
        \n\
        EXAMPLES:\n    \
            # CI gate: refuse to regenerate the MCP surface on a breaking change.\n    \
            sbproxy-mcp-drift --previous last.openapi.json --current current.openapi.json || exit $?\n    \
            # Gate a live MCP tools/list snapshot against a consumer cassette.\n    \
            sbproxy-mcp-drift --cassette session-ledger.ndjson --current-tools live-tools-list.json"
    );
}

#[derive(Debug, Default)]
struct Args {
    previous: Option<PathBuf>,
    current: Option<PathBuf>,
    cassette: Option<PathBuf>,
    current_tools: Option<PathBuf>,
    format: Format,
    help: bool,
}

#[derive(Debug, Clone, Copy, Default)]
enum Format {
    #[default]
    Text,
    Json,
}

fn parse_args(argv: Vec<String>) -> Result<Args, String> {
    let mut args = Args::default();
    let mut iter = argv.into_iter().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-h" | "--help" => args.help = true,
            "--previous" => {
                args.previous = Some(PathBuf::from(iter.next().ok_or("--previous needs a path")?));
            }
            "--current" => {
                args.current = Some(PathBuf::from(iter.next().ok_or("--current needs a path")?));
            }
            "--cassette" => {
                args.cassette = Some(PathBuf::from(iter.next().ok_or("--cassette needs a path")?));
            }
            "--current-tools" | "--live-tools" => {
                args.current_tools = Some(PathBuf::from(
                    iter.next().ok_or("--current-tools needs a path")?,
                ));
            }
            "--format" => {
                let fmt = iter.next().ok_or("--format needs a value")?;
                args.format = match fmt.as_str() {
                    "text" => Format::Text,
                    "json" => Format::Json,
                    other => return Err(format!("unknown --format `{other}`")),
                };
            }
            other => return Err(format!("unknown argument `{other}`; try --help")),
        }
    }
    Ok(args)
}

fn load_spec(path: &PathBuf) -> Result<serde_json::Value, String> {
    let bytes = fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    // Try JSON first, fall back to YAML. Most operators emit JSON
    // from their OpenAPI tooling; YAML is the codegen-native form.
    if let Ok(v) = serde_json::from_slice(&bytes) {
        return Ok(v);
    }
    serde_yaml::from_slice(&bytes).map_err(|e| format!("parsing {}: {e}", path.display()))
}

fn run() -> Result<i32, String> {
    let args = parse_args(std::env::args().collect())?;
    if args.help {
        print_usage();
        return Ok(0);
    }

    match (
        args.previous,
        args.current,
        args.cassette,
        args.current_tools,
    ) {
        (Some(previous), Some(current), None, None) => {
            let prev_spec = load_spec(&previous)?;
            let cur_spec = load_spec(&current)?;
            let report = diff_openapi(&prev_spec, &cur_spec);
            print_openapi_report(&report, args.format)?;
            Ok(report.severity.exit_code())
        }
        (None, None, Some(cassette), Some(current_tools)) => {
            let cassette_value = load_document(&cassette)?;
            let current_tools_value = load_document(&current_tools)?;
            let report = diff_cassette_values(
                cassette.display().to_string(),
                &cassette_value,
                &current_tools_value,
            );
            print_cassette_report(&report, args.format)?;
            Ok(report.severity.exit_code())
        }
        _ => Err(
            "choose either --previous/--current or --cassette/--current-tools; try --help"
                .to_string(),
        ),
    }
}

fn print_openapi_report(
    report: &sbproxy_extension::mcp::schema_drift::DriftReport,
    format: Format,
) -> Result<(), String> {
    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).map_err(|e| e.to_string())?
            );
        }
        Format::Text => {
            println!("overall severity: {}", report.severity.as_str());
            if report.changes.is_empty() {
                println!("(no changes)");
            } else {
                println!("changes ({}):", report.changes.len());
                let mut by_sev = [Vec::new(), Vec::new(), Vec::new()];
                for c in &report.changes {
                    let bucket = severity_bucket(c.severity);
                    by_sev[bucket].push(c);
                }
                // Print Breaking first so a `head`d output shows
                // the most important entries.
                for (label, idx) in [("breaking", 2), ("informational", 1)] {
                    let bucket = &by_sev[idx];
                    if bucket.is_empty() {
                        continue;
                    }
                    println!("  [{}]", label);
                    for c in bucket {
                        println!("    - {} ({})", c.summary, c.operation);
                    }
                }
            }
        }
    }
    Ok(())
}

fn print_cassette_report(report: &CassetteDriftReport, format: Format) -> Result<(), String> {
    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).map_err(|e| e.to_string())?
            );
        }
        Format::Text => {
            println!("cassette: {}", report.cassette);
            println!("overall severity: {}", report.severity.as_str());
            if report.changes.is_empty() {
                println!("(no changes)");
            } else {
                println!("changes ({}):", report.changes.len());
                let mut by_sev = [Vec::new(), Vec::new(), Vec::new()];
                for c in &report.changes {
                    by_sev[severity_bucket(c.severity)].push(c);
                }
                for (label, idx) in [("breaking", 2), ("informational", 1)] {
                    let bucket = &by_sev[idx];
                    if bucket.is_empty() {
                        continue;
                    }
                    println!("  [{}]", label);
                    for c in bucket {
                        match &c.field {
                            Some(field) => {
                                println!("    - {} (tool: {}, field: {})", c.summary, c.tool, field)
                            }
                            None => println!("    - {} (tool: {})", c.summary, c.tool),
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn severity_bucket(severity: DriftSeverity) -> usize {
    match severity {
        DriftSeverity::None => 0,
        DriftSeverity::Informational => 1,
        DriftSeverity::Breaking => 2,
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(64) // EX_USAGE
        }
    }
}

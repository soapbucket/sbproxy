// SPDX-License-Identifier: BUSL-1.1
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
//! ```
//!
//! YAML inputs are accepted; the tool parses with `serde_yaml`
//! (re-exported by `sbproxy-config`'s dep set).

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use sbproxy_extension::mcp::schema_drift::{diff_openapi, DriftSeverity};

fn print_usage() {
    eprintln!(
        "{}",
        r#"sbproxy-mcp-drift: classify OpenAPI changes by severity (WOR-486)

USAGE:
    sbproxy-mcp-drift --previous <FILE> --current <FILE> [--format text|json]

EXIT CODES:
    0   no drift
    1   informational changes only (description / optional-added / enum-widened)
    2   breaking changes (operation removed / required-removed / type-changed / enum-narrowed)

FORMATS:
    text  (default) human-readable summary grouped by severity
    json  structured `DriftReport` suitable for downstream tooling

EXAMPLES:
    # CI gate: refuse to regenerate the MCP surface on a breaking change.
    sbproxy-mcp-drift --previous last.openapi.json --current current.openapi.json || exit $?
"#
    );
}

#[derive(Debug, Default)]
struct Args {
    previous: Option<PathBuf>,
    current: Option<PathBuf>,
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
    let previous = args.previous.ok_or("missing --previous")?;
    let current = args.current.ok_or("missing --current")?;

    let prev_spec = load_spec(&previous)?;
    let cur_spec = load_spec(&current)?;
    let report = diff_openapi(&prev_spec, &cur_spec);

    match args.format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
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
                    let bucket = match c.severity {
                        DriftSeverity::None => 0,
                        DriftSeverity::Informational => 1,
                        DriftSeverity::Breaking => 2,
                    };
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

    Ok(report.severity.exit_code())
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

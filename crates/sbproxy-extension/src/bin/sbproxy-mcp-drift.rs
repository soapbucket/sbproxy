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
        "sbproxy-mcp-drift: classify MCP surface changes by severity\n\
        \n\
        USAGE:\n    \
            sbproxy-mcp-drift --previous <FILE> --current <FILE> [--format text|json]\n    \
            sbproxy-mcp-drift --cassette <FILE> --current-tools <FILE> [--format text|json]\n    \
            sbproxy-mcp-drift --lock-tools <FILE|-> --lockfile <OUT.yaml> [--generated-for <NAME>]\n    \
            sbproxy-mcp-drift --check-tools <FILE|-> --lockfile <LOCK.yaml> [--declared <FILE>] [--format text|json]\n\
        \n\
        EXIT CODES:\n    \
            0   no drift / lockfile check passed\n    \
            1   informational changes only (new or removed tools on --check-tools)\n    \
            2   breaking changes / version-bump violations\n\
        \n\
        FORMATS:\n    \
            text  (default) human-readable summary grouped by severity\n    \
            json  structured report suitable for downstream tooling\n\
        \n\
        TOOLS INPUT:\n    \
            --lock-tools/--check-tools accept a tools/list JSON dump: the full\n    \
            JSON-RPC response, the bare result object, or a plain tools array.\n    \
            Pass `-` to read stdin, so a live gateway pipes straight in.\n\
        \n\
        EXAMPLES:\n    \
            # Snapshot a live gateway into a committed lockfile.\n    \
            curl -s https://mcp.example.com/ -H 'content-type: application/json' \\\n        \
                 -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}' \\\n        \
                 | sbproxy-mcp-drift --lock-tools - --lockfile tool-versions.lock.yaml\n    \
            # CI gate: fail the build on an under-bumped contract change.\n    \
            sbproxy-mcp-drift --check-tools live-tools.json --lockfile tool-versions.lock.yaml"
    );
}

#[derive(Debug, Default)]
struct Args {
    previous: Option<PathBuf>,
    current: Option<PathBuf>,
    cassette: Option<PathBuf>,
    current_tools: Option<PathBuf>,
    lock_tools: Option<String>,
    check_tools: Option<String>,
    lockfile: Option<PathBuf>,
    declared: Option<PathBuf>,
    generated_for: Option<String>,
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
            "--lock-tools" => {
                args.lock_tools = Some(iter.next().ok_or("--lock-tools needs a path or -")?);
            }
            "--check-tools" => {
                args.check_tools = Some(iter.next().ok_or("--check-tools needs a path or -")?);
            }
            "--lockfile" => {
                args.lockfile = Some(PathBuf::from(iter.next().ok_or("--lockfile needs a path")?));
            }
            "--declared" => {
                args.declared = Some(PathBuf::from(iter.next().ok_or("--declared needs a path")?));
            }
            "--generated-for" => {
                args.generated_for = Some(iter.next().ok_or("--generated-for needs a value")?);
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

    if let Some(source) = args.lock_tools {
        let lockfile = args
            .lockfile
            .ok_or("--lock-tools needs --lockfile <OUT.yaml>")?;
        return lock_tools(&source, &lockfile, args.generated_for.as_deref());
    }
    if let Some(source) = args.check_tools {
        let lockfile = args
            .lockfile
            .ok_or("--check-tools needs --lockfile <LOCK.yaml>")?;
        return check_tools(&source, &lockfile, args.declared.as_deref(), args.format);
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

/// Read a tools/list dump from a file or stdin (`-`). Accepts the
/// full JSON-RPC response, the bare result object, or a plain array.
fn load_tools(source: &str) -> Result<Vec<serde_json::Value>, String> {
    let bytes = if source == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("reading stdin: {e}"))?;
        buf
    } else {
        fs::read(source).map_err(|e| format!("reading {source}: {e}"))?
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("parsing {source}: {e}"))?;
    let tools = value
        .get("result")
        .and_then(|r| r.get("tools"))
        .or_else(|| value.get("tools"))
        .unwrap_or(&value);
    let list = tools
        .as_array()
        .ok_or_else(|| format!("{source}: no tools array found"))?;
    for t in list {
        if t.get("name").and_then(|n| n.as_str()).is_none() {
            return Err(format!("{source}: a tool entry has no string `name`"));
        }
    }
    Ok(list.clone())
}

/// Generate (or refresh) a lockfile from a tools/list dump. Versions
/// carry over from an existing lockfile at the output path; new tools
/// start at 1.0.0. Bumps are declared by the operator (in sb.yml or
/// by editing the lockfile), never invented here.
fn lock_tools(
    source: &str,
    lockfile: &PathBuf,
    generated_for: Option<&str>,
) -> Result<i32, String> {
    use sbproxy_extension::mcp::compat::{contract_digest, Lockfile, ToolLock};

    let tools = load_tools(source)?;
    let prior: Option<Lockfile> = fs::read_to_string(lockfile)
        .ok()
        .and_then(|y| Lockfile::from_yaml(&y).ok());
    let mut locked = std::collections::BTreeMap::new();
    for tool in &tools {
        let name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        let semver = prior
            .as_ref()
            .and_then(|l| l.tools.get(&name))
            .map(|t| t.semver.clone())
            .unwrap_or_else(|| semver::Version::new(1, 0, 0));
        locked.insert(
            name,
            ToolLock {
                semver,
                contract_digest: contract_digest(tool),
                contract: Some(tool.clone()),
            },
        );
    }
    let count = locked.len();
    let out = Lockfile {
        version: 1,
        generated_for: generated_for
            .map(str::to_string)
            .or_else(|| prior.as_ref().map(|l| l.generated_for.clone()))
            .unwrap_or_else(|| "unspecified".to_string()),
        tools: locked,
    };
    fs::write(lockfile, out.to_yaml().map_err(|e| e.to_string())?)
        .map_err(|e| format!("writing {}: {e}", lockfile.display()))?;
    println!("locked {count} tool(s) into {}", lockfile.display());
    Ok(0)
}

/// One row of the check report.
#[derive(serde::Serialize)]
struct CheckFinding {
    tool: String,
    status: &'static str,
    grade: Option<String>,
    detail: String,
}

/// Check a tools/list dump against a lockfile: recompute digests,
/// grade changes, lint declared bumps. Violations exit 2, new or
/// removed tools alone exit 1, a clean run exits 0.
fn check_tools(
    source: &str,
    lockfile_path: &PathBuf,
    declared: Option<&std::path::Path>,
    format: Format,
) -> Result<i32, String> {
    use sbproxy_extension::mcp::compat::{
        contract_digest, evaluate_compatibility, lint_bump, BumpVerdict, CompatibilityVerdict,
        Lockfile, OracleInputs, SemverGrade,
    };

    let tools = load_tools(source)?;
    let lockfile = Lockfile::from_yaml(
        &fs::read_to_string(lockfile_path)
            .map_err(|e| format!("reading {}: {e}", lockfile_path.display()))?,
    )
    .map_err(|e| format!("parsing {}: {e}", lockfile_path.display()))?;
    let declared_versions: std::collections::BTreeMap<String, semver::Version> = match declared {
        None => Default::default(),
        Some(path) => {
            let raw: std::collections::BTreeMap<String, String> = serde_yaml::from_str(
                &fs::read_to_string(path)
                    .map_err(|e| format!("reading {}: {e}", path.display()))?,
            )
            .map_err(|e| format!("parsing {}: {e}", path.display()))?;
            raw.into_iter()
                .map(|(k, v)| match v.parse::<semver::Version>() {
                    Ok(parsed) => Ok((k, parsed)),
                    Err(e) => Err(format!("declared version for `{k}` is not semver: {e}")),
                })
                .collect::<Result<_, _>>()?
        }
    };

    let mut findings: Vec<CheckFinding> = Vec::new();
    let mut exit = 0;
    let mut seen = std::collections::BTreeSet::new();
    for tool in &tools {
        let name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        seen.insert(name.clone());
        let Some(lock) = lockfile.tools.get(&name) else {
            findings.push(CheckFinding {
                tool: name,
                status: "new",
                grade: None,
                detail: "tool is not in the lockfile baseline".to_string(),
            });
            exit = exit.max(1);
            continue;
        };
        let live_digest = contract_digest(tool);
        if live_digest == lock.contract_digest {
            continue;
        }
        let verdict: CompatibilityVerdict = match lock.contract.as_ref() {
            Some(old_contract) => evaluate_compatibility(&OracleInputs {
                tool: &name,
                old_tool: old_contract,
                new_tool: tool,
                old_response: None,
                new_response: None,
            }),
            None => CompatibilityVerdict {
                tool: name.clone(),
                from_digest: lock.contract_digest.clone(),
                to_digest: live_digest,
                grade: SemverGrade::Patch,
                findings: Vec::new(),
                behavioral_evaluated: false,
                needs_confirmation: false,
            },
        };
        let grade = format!("{:?}", verdict.grade).to_lowercase();
        let declared_version = declared_versions.get(&name).unwrap_or(&lock.semver);
        match lint_bump(&lock.semver, declared_version, &verdict) {
            BumpVerdict::Ok => findings.push(CheckFinding {
                tool: name,
                status: "changed_ok",
                grade: Some(grade),
                detail: format!(
                    "contract changed; declared {} -> {} covers the {} grade",
                    lock.semver,
                    declared_version,
                    format!("{:?}", verdict.grade).to_lowercase()
                ),
            }),
            BumpVerdict::Violation { detail, .. } => {
                findings.push(CheckFinding {
                    tool: name,
                    status: "violation",
                    grade: Some(grade),
                    detail,
                });
                exit = 2;
            }
        }
    }
    for name in lockfile.tools.keys() {
        if !seen.contains(name) {
            findings.push(CheckFinding {
                tool: name.clone(),
                status: "removed",
                grade: None,
                detail: "locked tool is no longer advertised".to_string(),
            });
            exit = exit.max(1);
        }
    }

    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "lockfile": lockfile_path.display().to_string(),
                "findings": findings,
                "pass": exit != 2,
            }))
            .map_err(|e| e.to_string())?
        ),
        Format::Text => {
            if findings.is_empty() {
                println!("lockfile check passed: {} tool(s) unchanged", tools.len());
            } else {
                println!("lockfile check findings ({}):", findings.len());
                for f in &findings {
                    match &f.grade {
                        Some(g) => println!("  [{}] {} ({}): {}", f.status, f.tool, g, f.detail),
                        None => println!("  [{}] {}: {}", f.status, f.tool, f.detail),
                    }
                }
                println!("result: {}", if exit == 2 { "FAIL" } else { "pass" });
            }
        }
    }
    Ok(exit)
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

#[cfg(test)]
mod lock_check_tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sbproxy-drift-{}-{}", std::process::id(), name))
    }

    fn tools_dump(description: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [
                {"name": "search", "description": description,
                 "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}
            ]}
        })
        .to_string()
    }

    #[test]
    fn generate_then_check_unchanged_exits_zero() {
        let dump = temp("dump.json");
        let lock = temp("clean.lock.yaml");
        std::fs::write(&dump, tools_dump("original")).unwrap();
        let code = lock_tools(dump.to_str().unwrap(), &lock, Some("test")).unwrap();
        assert_eq!(code, 0);
        let code = check_tools(dump.to_str().unwrap(), &lock, None, Format::Text).unwrap();
        assert_eq!(code, 0, "unchanged catalogue must pass");
        let _ = std::fs::remove_file(dump);
        let _ = std::fs::remove_file(lock);
    }

    #[test]
    fn under_bump_exits_two() {
        let dump = temp("dump2.json");
        let lock = temp("under.lock.yaml");
        std::fs::write(&dump, tools_dump("original")).unwrap();
        lock_tools(dump.to_str().unwrap(), &lock, None).unwrap();
        // Contract changes, no declared bump: violation.
        std::fs::write(&dump, tools_dump("something else entirely")).unwrap();
        let code = check_tools(dump.to_str().unwrap(), &lock, None, Format::Text).unwrap();
        assert_eq!(code, 2, "changed contract with no bump must fail");
        let _ = std::fs::remove_file(dump);
        let _ = std::fs::remove_file(lock);
    }

    #[test]
    fn over_bump_passes() {
        let dump = temp("dump3.json");
        let lock = temp("over.lock.yaml");
        let declared = temp("declared.yaml");
        std::fs::write(&dump, tools_dump("original")).unwrap();
        lock_tools(dump.to_str().unwrap(), &lock, None).unwrap();
        std::fs::write(&dump, tools_dump("reworded")).unwrap();
        // A major bump over a patch-grade change is allowed.
        std::fs::write(&declared, "search: \"2.0.0\"\n").unwrap();
        let code = check_tools(
            dump.to_str().unwrap(),
            &lock,
            Some(declared.as_path()),
            Format::Json,
        )
        .unwrap();
        assert_eq!(code, 0, "over-bumping is allowed");
        let _ = std::fs::remove_file(dump);
        let _ = std::fs::remove_file(lock);
        let _ = std::fs::remove_file(declared);
    }

    #[test]
    fn new_tool_is_informational() {
        let dump = temp("dump4.json");
        let lock = temp("new.lock.yaml");
        std::fs::write(&dump, tools_dump("original")).unwrap();
        lock_tools(dump.to_str().unwrap(), &lock, None).unwrap();
        let two_tools = serde_json::json!({"tools": [
            {"name": "search", "description": "original",
             "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
            {"name": "brand_new", "description": "n", "inputSchema": {"type": "object"}}
        ]})
        .to_string();
        std::fs::write(&dump, two_tools).unwrap();
        let code = check_tools(dump.to_str().unwrap(), &lock, None, Format::Text).unwrap();
        assert_eq!(code, 1, "a new tool alone is informational");
        let _ = std::fs::remove_file(dump);
        let _ = std::fs::remove_file(lock);
    }

    #[test]
    fn lock_preserves_prior_versions() {
        let dump = temp("dump5.json");
        let lock = temp("carry.lock.yaml");
        std::fs::write(&dump, tools_dump("original")).unwrap();
        lock_tools(dump.to_str().unwrap(), &lock, None).unwrap();
        // Manually bump the locked version, regenerate, and confirm
        // the version carries over instead of resetting to 1.0.0.
        let mut parsed = sbproxy_extension::mcp::compat::Lockfile::from_yaml(
            &std::fs::read_to_string(&lock).unwrap(),
        )
        .unwrap();
        parsed.tools.get_mut("search").unwrap().semver = semver::Version::new(3, 2, 1);
        std::fs::write(&lock, parsed.to_yaml().unwrap()).unwrap();
        lock_tools(dump.to_str().unwrap(), &lock, None).unwrap();
        let reparsed = sbproxy_extension::mcp::compat::Lockfile::from_yaml(
            &std::fs::read_to_string(&lock).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reparsed.tools["search"].semver,
            semver::Version::new(3, 2, 1)
        );
        let _ = std::fs::remove_file(dump);
        let _ = std::fs::remove_file(lock);
    }
}

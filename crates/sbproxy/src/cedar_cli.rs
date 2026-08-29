//! `sbproxy cedar replay`: evaluate recorded MCP tool-call samples
//! against Cedar source from an `sb.yml`, optionally diffed against a
//! baseline config.
//!
//! Lives in its own module so the JSONL / compile / report path is
//! testable without going through clap. The clap types stay in
//! `main.rs` next to the other subcommands.
//!
//! Replay matches one live MCP hook: a single origin's
//! `cedar_policies` compiled with [`merged_schema`] (default MCP
//! schema plus that origin's `schema_override`). Concatenating every
//! origin into one `PolicySet` would mix forbids across gateways.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use sbproxy_extension::cedar::{
    compile_all, format_text, parse_jsonl, replay,
    schema::{merged_schema, McpSchemaConfig},
    CedarEvaluator, ReplayReport,
};

/// One origin's Cedar block, the same unit the live hook compiles.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CedarOriginSource {
    host: String,
    policies: String,
    schema_override: Option<String>,
}

/// Arguments for `sbproxy cedar replay`.
#[derive(Debug, Clone)]
pub(crate) struct CedarReplayRequest {
    /// Proposed `sb.yml` (or a YAML that at least contains
    /// `origins.*.action.cedar_policies`).
    pub config: PathBuf,
    /// JSONL traffic sample.
    pub against: PathBuf,
    /// Optional baseline `sb.yml`. When set, the report diffs verdicts.
    pub baseline: Option<PathBuf>,
    /// Restrict extraction to one origin hostname. Required when the
    /// document has more than one Cedar origin.
    pub origin: Option<String>,
    /// `text` or `json`.
    pub json: bool,
}

/// Run replay. Exit 0 when every assertion held and no baseline
/// verdict moved; 1 when a sample missed; 2 is reserved for the
/// caller (`run_subcommand`) on `Err`.
pub(crate) fn handle_cedar_replay(req: &CedarReplayRequest) -> anyhow::Result<i32> {
    let proposed_yaml = std::fs::read_to_string(&req.config)
        .with_context(|| format!("read {}", req.config.display()))?;
    let proposed_src = select_one_origin(cedar_sources_from_yaml(
        &proposed_yaml,
        req.origin.as_deref(),
    )?)?;
    let proposed = evaluator_from_origin(&proposed_src)?;

    let baseline = if let Some(path) = req.baseline.as_ref() {
        let yaml =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let src = select_one_origin(cedar_sources_from_yaml(&yaml, req.origin.as_deref())?)?;
        Some(evaluator_from_origin(&src)?)
    } else {
        None
    };

    let sample_text = std::fs::read_to_string(&req.against)
        .with_context(|| format!("read {}", req.against.display()))?;
    let samples = parse_jsonl(&sample_text).map_err(|error| anyhow!("{error}"))?;
    if samples.is_empty() {
        return Err(anyhow!(
            "traffic sample {} is empty (no JSON objects)",
            req.against.display()
        ));
    }

    let report = replay(&proposed, baseline.as_ref(), &samples);
    print_report(&report, req.json, &req.against)?;
    Ok(if report.ok() { 0 } else { 1 })
}

fn print_report(report: &ReplayReport, json: bool, sample_path: &Path) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        print!("{}", format_text(report));
        eprintln!(
            "cedar replay: {} ({} sample{})",
            sample_path.display(),
            report.rows.len(),
            if report.rows.len() == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

/// Compile the way the live MCP action does: one origin, merged schema,
/// policy id `cedar_policies`.
fn evaluator_from_origin(source: &CedarOriginSource) -> anyhow::Result<CedarEvaluator> {
    let schema_config = McpSchemaConfig {
        mcp_primitives_enabled: true,
        workspace_override: source.schema_override.clone(),
    };
    let (schema, _) = merged_schema(&schema_config)
        .map_err(|error| anyhow!("origin '{}': {error}", source.host))?
        .ok_or_else(|| {
            anyhow!(
                "origin '{}': default MCP schema unexpectedly disabled",
                source.host
            )
        })?;
    let compiled = compile_all(
        &[("cedar_policies", source.policies.as_str())],
        Some(&schema),
    )
    .map_err(|error| anyhow!("origin '{}': {error}", source.host))?;
    CedarEvaluator::new(compiled.policy_set, Some(schema))
        .map_err(|error| anyhow!("origin '{}': {error}", source.host))
}

/// Live evaluation is one hook per origin. Mixing two Cedar sets into
/// one PolicySet would let origin B's catch-all forbid deny origin A's
/// traffic, which the live path never does.
fn select_one_origin(mut sources: Vec<CedarOriginSource>) -> anyhow::Result<CedarOriginSource> {
    match sources.len() {
        0 => Err(anyhow!("no origins.*.action.cedar_policies.policies found")),
        1 => Ok(sources.remove(0)),
        _ => {
            let hosts: Vec<&str> = sources.iter().map(|s| s.host.as_str()).collect();
            Err(anyhow!(
                "multiple origins have cedar_policies ({}); pass --origin so replay matches one live hook",
                hosts.join(", ")
            ))
        }
    }
}

/// Pull every `origins.<host>.action.cedar_policies` block.
///
/// # Errors
///
/// Returns when the document is not YAML, has no matching Cedar
/// block, or `--origin` names a host that has none.
fn cedar_sources_from_yaml(
    yaml: &str,
    origin_filter: Option<&str>,
) -> anyhow::Result<Vec<CedarOriginSource>> {
    let doc: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|error| anyhow!("parse YAML: {error}"))?;
    let Some(origins) = doc.get("origins").and_then(|v| v.as_mapping()) else {
        return Err(anyhow!("YAML has no origins: map"));
    };
    let mut sources = Vec::new();
    for (key, origin) in origins {
        let Some(host) = key.as_str() else {
            continue;
        };
        if let Some(filter) = origin_filter {
            if host != filter {
                continue;
            }
        }
        let Some(cedar) = origin.get("action").and_then(|a| a.get("cedar_policies")) else {
            continue;
        };
        let Some(policies) = cedar.get("policies").and_then(|p| p.as_str()) else {
            continue;
        };
        if policies.trim().is_empty() {
            continue;
        }
        let schema_override = cedar
            .get("schema_override")
            .and_then(|p| p.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        sources.push(CedarOriginSource {
            host: host.to_string(),
            policies: policies.to_string(),
            schema_override,
        });
    }
    if sources.is_empty() {
        return Err(match origin_filter {
            Some(host) => anyhow!("origin '{host}' has no cedar_policies.policies block"),
            None => anyhow!("no origins.*.action.cedar_policies.policies found"),
        });
    }
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
origins:
  mcp.example.com:
    action:
      type: mcp
      cedar_policies:
        policies: |
          permit(principal, action, resource);
        schema_override: |
          entity AcmeWidget = {
            sku: String,
          };
  other.example.com:
    action:
      type: proxy
      url: https://example.com
"#;

    const TWO_CEDAR: &str = r#"
origins:
  a.example.com:
    action:
      type: mcp
      cedar_policies:
        policies: |
          permit(principal, action, resource);
  b.example.com:
    action:
      type: mcp
      cedar_policies:
        policies: |
          forbid(principal, action, resource);
"#;

    #[test]
    fn extracts_cedar_from_mcp_origin() {
        let sources = cedar_sources_from_yaml(YAML, None).expect("extract");
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].host, "mcp.example.com");
        assert!(sources[0].policies.contains("permit("));
        assert!(sources[0]
            .schema_override
            .as_deref()
            .is_some_and(|s| s.contains("AcmeWidget")));
    }

    #[test]
    fn origin_filter_miss_is_an_error() {
        let err =
            cedar_sources_from_yaml(YAML, Some("missing.example.com")).expect_err("must fail");
        assert!(err.to_string().contains("missing.example.com"));
    }

    #[test]
    fn two_cedar_origins_require_origin_flag() {
        let sources = cedar_sources_from_yaml(TWO_CEDAR, None).expect("extract");
        let err = select_one_origin(sources).expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.contains("--origin"), "{msg}");
        assert!(msg.contains("a.example.com"), "{msg}");
        assert!(msg.contains("b.example.com"), "{msg}");
    }

    #[test]
    fn origin_flag_picks_one_of_two_cedar_origins() {
        let sources = cedar_sources_from_yaml(TWO_CEDAR, Some("a.example.com")).expect("extract");
        let one = select_one_origin(sources).expect("one");
        assert_eq!(one.host, "a.example.com");
        assert!(one.policies.contains("permit("));
    }

    #[test]
    fn evaluator_uses_schema_override_the_live_hook_would() {
        let sources = cedar_sources_from_yaml(YAML, None).expect("extract");
        let one = select_one_origin(sources).expect("one");
        evaluator_from_origin(&one).expect("compile with AcmeWidget override");
    }
}

//! `sbproxy cedar replay`: evaluate recorded MCP tool-call samples
//! against Cedar source from an `sb.yml`, optionally diffed against a
//! baseline config.
//!
//! Lives in its own module so the JSONL / compile / report path is
//! testable without going through clap. The clap types stay in
//! `main.rs` next to the other subcommands.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use sbproxy_extension::cedar::{
    compile_all, format_text, parse_jsonl, replay, schema::default_schema, CedarEvaluator,
    ReplayReport,
};

/// Arguments for `sbproxy cedar replay`.
#[derive(Debug, Clone)]
pub struct CedarReplayRequest {
    /// Proposed `sb.yml` (or a YAML that at least contains
    /// `origins.*.action.cedar_policies`).
    pub config: PathBuf,
    /// JSONL traffic sample.
    pub against: PathBuf,
    /// Optional baseline `sb.yml`. When set, the report diffs verdicts.
    pub baseline: Option<PathBuf>,
    /// Restrict extraction to one origin hostname.
    pub origin: Option<String>,
    /// `text` or `json`.
    pub json: bool,
}

/// Run replay. Exit 0 when every assertion held and no baseline
/// verdict moved; 1 when a sample missed; 2 is reserved for the
/// caller (`run_subcommand`) on `Err`.
pub fn handle_cedar_replay(req: &CedarReplayRequest) -> anyhow::Result<i32> {
    let proposed_yaml = std::fs::read_to_string(&req.config)
        .with_context(|| format!("read {}", req.config.display()))?;
    let proposed_src = cedar_sources_from_yaml(&proposed_yaml, req.origin.as_deref())?;
    let proposed = evaluator_from_sources(&proposed_src)?;

    let baseline = if let Some(path) = req.baseline.as_ref() {
        let yaml =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let src = cedar_sources_from_yaml(&yaml, req.origin.as_deref())?;
        Some(evaluator_from_sources(&src)?)
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

fn evaluator_from_sources(sources: &[(String, String)]) -> anyhow::Result<CedarEvaluator> {
    let refs: Vec<(&str, &str)> = sources
        .iter()
        .map(|(id, src)| (id.as_str(), src.as_str()))
        .collect();
    let (schema, _) = default_schema().map_err(|error| anyhow!("default MCP schema: {error}"))?;
    let compiled = compile_all(&refs, Some(&schema)).map_err(|error| anyhow!("{error}"))?;
    CedarEvaluator::new(compiled.policy_set, Some(schema)).map_err(|error| anyhow!("{error}"))
}

/// Pull every `origins.<host>.action.cedar_policies.policies` string.
///
/// # Errors
///
/// Returns when the document is not YAML, has no matching Cedar
/// block, or `--origin` names a host that has none.
pub fn cedar_sources_from_yaml(
    yaml: &str,
    origin_filter: Option<&str>,
) -> anyhow::Result<Vec<(String, String)>> {
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
        let Some(policies) = origin
            .get("action")
            .and_then(|a| a.get("cedar_policies"))
            .and_then(|c| c.get("policies"))
            .and_then(|p| p.as_str())
        else {
            continue;
        };
        if policies.trim().is_empty() {
            continue;
        }
        sources.push((host.to_string(), policies.to_string()));
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
  other.example.com:
    action:
      type: proxy
      url: https://example.com
"#;

    #[test]
    fn extracts_cedar_from_mcp_origin() {
        let sources = cedar_sources_from_yaml(YAML, None).expect("extract");
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].0, "mcp.example.com");
        assert!(sources[0].1.contains("permit("));
    }

    #[test]
    fn origin_filter_miss_is_an_error() {
        let err =
            cedar_sources_from_yaml(YAML, Some("missing.example.com")).expect_err("must fail");
        assert!(err.to_string().contains("missing.example.com"));
    }
}

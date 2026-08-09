// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The runbook index guard.
//!
//! A paging alert carries a `runbook_id` label so that on-call gets a stable
//! correlation key rather than an alert name that changes when somebody
//! retitles a rule. The key is only worth carrying if it resolves. Every one of
//! the eleven ids shipped in `deploy/alerts/alerting-rules.yml` resolved to
//! nothing until this guard landed: `docs/operator-runbook.md` did not contain
//! the string `RB-` at all, so a page at 3am handed the responder an identifier
//! with no lookup behind it, and the header comment in the rules file claimed
//! the opposite ("section ids match runbook_id labels").
//!
//! That is a documentation gap that repairs itself exactly once and then decays
//! on the next alert somebody adds, which is what this file is for. Four
//! directions are checked, because a one-way check leaves the other three free:
//!
//! - a rule emits an id the index does not list (the original defect);
//! - an index row points at a section heading that is not in the document;
//! - an index row names an id no rule emits, which is a row that outlived its
//!   alert and sends a reader looking for an incident that cannot happen;
//! - a `runbook_url` annotation ends in a fragment that is not an indexed id,
//!   which is the third copy of the same key and the one nothing else reads.
//!
//! The anchor convention is load bearing and is enforced rather than assumed. A
//! section heading is the id and nothing else, so its GitHub anchor is the id
//! lowercased. Put a human title in the heading instead and the anchor becomes
//! a slug of that title, which means rewording the title silently breaks every
//! link an alert has already shipped to a pager.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sbproxy-observe -> crates -> repo root")
        .to_path_buf()
}

/// Where an id was written, so a failure names the file and rule to fix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    /// The id or URL fragment as written.
    value: String,
    /// The enclosing `- alert:` or `alertname:`, or `?` outside a rule.
    rule: String,
    /// Path relative to the repo root.
    file: String,
    /// One-based line number.
    line: usize,
}

impl std::fmt::Display for Site {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} on {} ({}:{})",
            self.value, self.rule, self.file, self.line
        )
    }
}

/// The scalar a `key: value` or `"key": "value"` line carries.
///
/// Both spellings are read because a rule set can ship as YAML or inside a
/// Grafana dashboard's JSON, and a guard that only understands one of them
/// stops working the day somebody adds the other. Splitting on the first colon
/// after the key handles both: in JSON the closing quote of the key falls
/// before that colon and is trimmed with the rest.
///
/// Returns `None` for a line with no colon after the key, which is how prose
/// mentioning the key in a comment stays out of the result set. The rules file
/// has two such comments and both named ids that would otherwise be indicted.
fn scalar_after(line: &str, key: &str) -> Option<String> {
    let at = line.find(key)?;
    let (_, after) = line[at + key.len()..].split_once(':')?;
    let value = after
        .trim()
        .trim_end_matches(',')
        .trim()
        .trim_matches('"')
        .trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// The rule name a line opens, if it opens one.
///
/// `- alert:` is a rule in an alerting-rules file. `alertname:` is the same
/// rule named from a promtool unit test, which asserts on the labels the rule
/// emits and is therefore a third place an id can be written and get stale.
fn rule_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if let Some(name) = trimmed.strip_prefix("- alert:") {
        return Some(name.trim().trim_matches('"').to_string());
    }
    if trimmed.starts_with("alertname:") {
        return scalar_after(trimmed, "alertname");
    }
    None
}

/// Every `runbook_id` and `runbook_url` written in one file's text.
fn sites_in(text: &str, file: &str) -> (Vec<Site>, Vec<Site>) {
    let mut ids = Vec::new();
    let mut urls = Vec::new();
    let mut rule = String::from("?");

    for (index, line) in text.lines().enumerate() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some(name) = rule_name(line) {
            rule = name;
        }
        let at = |value: String| Site {
            value,
            rule: rule.clone(),
            file: file.to_string(),
            line: index + 1,
        };
        if let Some(value) = scalar_after(line, "runbook_id") {
            ids.push(at(value));
        }
        if let Some(value) = scalar_after(line, "runbook_url") {
            urls.push(at(value));
        }
    }

    (ids, urls)
}

/// Walk `dashboards/` and `deploy/` for anything that can carry alert labels.
///
/// Recursive on purpose. The metric scanner in `sbproxy-capability` reads a
/// fixed list of four directories non-recursively, which is right for it and
/// wrong here: `deploy/alerts/tests/` already sits one level down, and a new
/// rule file dropped into a new subdirectory would otherwise be invisible to
/// this guard while still shipping ids to a pager.
fn rule_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                walk(&path, out);
            } else if matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("yml") | Some("yaml") | Some("json")
            ) {
                out.push(path);
            }
        }
    }

    let mut out = Vec::new();
    for dir in ["dashboards", "deploy"] {
        walk(&root.join(dir), &mut out);
    }
    out
}

/// Every id and url fragment any alert rule in the tree can emit.
fn emitted(root: &Path) -> (Vec<Site>, Vec<Site>) {
    let mut ids = Vec::new();
    let mut urls = Vec::new();

    for path in rule_files(root) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let file = path
            .strip_prefix(root)
            .unwrap_or(path.as_path())
            .to_string_lossy()
            .into_owned();
        let (file_ids, file_urls) = sites_in(&text, &file);
        ids.extend(file_ids);
        urls.extend(file_urls);
    }

    (ids, urls)
}

const RUNBOOK: &str = "docs/operator-runbook.md";

/// The id and anchor an index row names, or `None` for any other line.
///
/// Matched on the row's shape rather than on a heading position, for the reason
/// the cardinality-budget parser in `metric_drift.rs` is: prose elsewhere in
/// this document puts ids in backticks too, and the alert-response sections
/// each open with a backticked rule name. An index row is specifically a table
/// cell holding a backticked id wrapped in a link to a fragment.
fn index_row(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("| [`")?;
    let (id, rest) = rest.split_once("`](#")?;
    let (anchor, _) = rest.split_once(')')?;
    id.starts_with("RB-")
        .then(|| (id.to_string(), anchor.to_string()))
}

/// The id a section heading declares, or `None` for any other heading.
fn section_id(line: &str) -> Option<&str> {
    let text = line.strip_prefix("### ")?.trim();
    text.starts_with("RB-").then_some(text)
}

/// The index rows, keyed by id, and every `### RB-*` heading in the document.
fn runbook(root: &Path) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let doc = std::fs::read_to_string(root.join(RUNBOOK)).expect("read docs/operator-runbook.md");

    let mut rows = BTreeMap::new();
    let mut sections = BTreeSet::new();
    for line in doc.lines() {
        if let Some((id, anchor)) = index_row(line) {
            rows.insert(id, anchor);
        }
        if let Some(id) = section_id(line) {
            sections.insert(id.to_string());
        }
    }

    (rows, sections)
}

fn listed(what: &str, offenders: &[String]) -> String {
    let body = offenders
        .iter()
        .map(|offender| format!("  - {offender}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{what}\n\n{body}\n")
}

#[test]
fn every_alert_runbook_id_resolves_to_an_index_entry() {
    let root = repo_root();
    let (ids, _) = emitted(&root);
    let (rows, _) = runbook(&root);

    // Floors guard the two parsers, not the counts. A shape matcher that
    // quietly stops matching turns the assertion below into a claim about the
    // empty set, which is exactly the state this guard was written to end.
    assert!(
        ids.len() >= 12,
        "found only {} runbook_id labels under dashboards/ and deploy/; the label \
         scanner is not reading the files it thinks it is",
        ids.len()
    );
    assert!(
        rows.len() >= 10,
        "parsed only {} rows out of the {RUNBOOK} alert index; the row parser is not \
         reading the table it thinks it is",
        rows.len()
    );

    // One concrete pairing, so the floor above cannot be met by ids the
    // scanner invented out of prose or comments.
    assert!(
        ids.iter().any(|site| {
            site.file == "deploy/alerts/alerting-rules.yml"
                && site.value == "RB-METER-CHAIN-GAP"
                && site.rule == "SBPROXY-METER-CHAIN-GAP"
        }),
        "the meter chain-gap rule's runbook_id was not scanned"
    );

    let offenders: Vec<String> = ids
        .iter()
        .filter(|site| !rows.contains_key(&site.value))
        .map(Site::to_string)
        .collect();

    assert!(
        offenders.is_empty(),
        "{}",
        listed(
            "An alert rule emits a runbook_id that the alert index in \
             docs/operator-runbook.md does not list. On-call gets a correlation key that \
             looks up to nothing. Add a row to the index and a `### <ID>` section under \
             Alert responses:",
            &offenders,
        )
    );
}

#[test]
fn every_runbook_id_is_shaped_like_an_anchor() {
    // The anchor convention only survives if the ids do. A lowercase id, a
    // space, or a stray character gives a heading whose GitHub anchor is not
    // the id, and the link in the index would then have to be hand-corrected
    // to something no alert emits.
    let (ids, _) = emitted(&repo_root());

    let offenders: Vec<String> = ids
        .iter()
        .filter(|site| {
            let id = &site.value;
            !id.starts_with("RB-")
                || id.len() <= 3
                || id.ends_with('-')
                || id.contains("--")
                || !id.chars().all(|value| {
                    value.is_ascii_uppercase() || value.is_ascii_digit() || value == '-'
                })
        })
        .map(Site::to_string)
        .collect();

    assert!(
        offenders.is_empty(),
        "{}",
        listed(
            "A runbook_id is not of the form RB-UPPER-CASE-WORDS. The runbook derives each \
             section anchor by lowercasing the id, so an id outside that shape cannot have \
             a stable anchor:",
            &offenders,
        )
    );
}

#[test]
fn every_index_entry_points_at_a_section_that_exists() {
    let root = repo_root();
    let (rows, sections) = runbook(&root);

    assert!(
        sections.len() >= 10,
        "found only {} `### RB-*` headings in {RUNBOOK}; the heading parser is not reading \
         the sections it thinks it is",
        sections.len()
    );

    let mut offenders = Vec::new();
    for (id, anchor) in &rows {
        let expected = id.to_lowercase();
        if anchor != &expected {
            offenders.push(format!(
                "{id} links to #{anchor}, but its section anchor is #{expected}"
            ));
        }
        if !sections.contains(id) {
            offenders.push(format!(
                "{id} is indexed but has no `### {id}` section under Alert responses"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "{}",
        listed(
            "The alert index in docs/operator-runbook.md points somewhere the document does \
             not go. A heading must be the id alone, so that its anchor is the id lowercased \
             and stays put when the section is rewritten:",
            &offenders,
        )
    );
}

#[test]
fn every_index_entry_names_an_id_some_alert_emits() {
    // The reverse direction. A row nobody can reach is not harmless: it reads
    // as coverage during an audit, and at 3am it sends a responder looking for
    // an incident that no rule in this repository can raise.
    let root = repo_root();
    let (ids, _) = emitted(&root);
    let (rows, _) = runbook(&root);

    let live: BTreeSet<&str> = ids.iter().map(|site| site.value.as_str()).collect();
    let offenders: Vec<String> = rows
        .keys()
        .filter(|id| !live.contains(id.as_str()))
        .cloned()
        .collect();

    assert!(
        offenders.is_empty(),
        "{}",
        listed(
            "The alert index in docs/operator-runbook.md lists a runbook_id that no alert \
             rule under dashboards/ or deploy/ emits. Either the rule was deleted and the \
             row should go with it, or the rule was never wired:",
            &offenders,
        )
    );
}

#[test]
fn every_runbook_url_annotation_ends_at_an_indexed_id() {
    // The third copy of the key. `runbook_url` is what an Alertmanager
    // template renders into the notification, so a fragment that drifts from
    // its own rule's runbook_id is a link that opens the wrong section while
    // the label next to it says something else.
    let root = repo_root();
    let (_, urls) = emitted(&root);
    let (rows, _) = runbook(&root);

    assert!(
        urls.len() >= 12,
        "found only {} runbook_url annotations; the scanner is not reading the rules",
        urls.len()
    );

    let anchors: BTreeSet<String> = rows.keys().map(|id| id.to_lowercase()).collect();
    let offenders: Vec<String> = urls
        .iter()
        .filter(|site| match site.value.split_once('#') {
            Some((_, fragment)) => !anchors.contains(fragment),
            None => true,
        })
        .map(Site::to_string)
        .collect();

    assert!(
        offenders.is_empty(),
        "{}",
        listed(
            "A runbook_url annotation has no fragment, or a fragment that is not an indexed \
             runbook_id lowercased. The link in the page notification would land on the \
             runbook and then nowhere:",
            &offenders,
        )
    );
}

/// A rule carrying both keys, in both spellings, plus the two shapes that must
/// not be picked up: a comment naming the label, and a rule whose name has to
/// carry through to the id below it.
const SYNTHETIC: &str = r#"
# severity / slo_id / runbook_id label conventions are defined here.
groups:
  - name: synthetic
    rules:
      - alert: SBPROXY-SYNTHETIC
        labels:
          runbook_id: RB-SYNTHETIC
        annotations:
          runbook_url: "https://docs.sbproxy.dev/runbook#rb-synthetic"
      - alert: SBPROXY-JSON-SHAPED
        "runbook_id": "RB-JSON",
"#;

#[test]
fn the_scanner_reads_both_spellings_and_skips_comments() {
    // The guards above are all assertions that a set is empty, and an empty
    // set is also what a scanner that has stopped scanning returns. The floors
    // catch that for the real tree; this catches it for the parser itself,
    // including the comment line that names the label and must stay out.
    let (ids, urls) = sites_in(SYNTHETIC, "synthetic.yml");

    let found: Vec<(&str, &str)> = ids
        .iter()
        .map(|site| (site.value.as_str(), site.rule.as_str()))
        .collect();
    assert_eq!(
        found,
        vec![
            ("RB-SYNTHETIC", "SBPROXY-SYNTHETIC"),
            ("RB-JSON", "SBPROXY-JSON-SHAPED"),
        ],
        "the label scanner missed a spelling, or read the comment on line 2 as a label"
    );

    assert_eq!(
        urls.iter()
            .map(|site| site.value.as_str())
            .collect::<Vec<_>>(),
        vec!["https://docs.sbproxy.dev/runbook#rb-synthetic"],
        "the annotation scanner did not read the runbook_url"
    );
}

#[test]
fn the_index_parser_reads_a_row_and_ignores_the_prose_around_it() {
    assert_eq!(
        index_row("| [`RB-AUDIT-WRITE`](#rb-audit-write) | `SBPROXY-AUDIT-WRITE-FAILURE` | page |"),
        Some(("RB-AUDIT-WRITE".to_string(), "rb-audit-write".to_string()))
    );
    assert_eq!(index_row("| `RB-AUDIT-WRITE` | not a link | page |"), None);
    assert_eq!(
        index_row("Look `RB-AUDIT-WRITE` up in the index below."),
        None
    );
    assert_eq!(section_id("### RB-AUDIT-WRITE"), Some("RB-AUDIT-WRITE"));
    assert_eq!(section_id("### Triage and rollback"), None);
    assert_eq!(section_id("## Alert responses"), None);
}

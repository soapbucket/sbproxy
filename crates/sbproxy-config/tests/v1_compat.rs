//! The flat v0.1.x Go `sb.yml` shape is refused, not translated.
//!
//! Go compatibility is deprecated. The archived Go line put a single
//! origin's behavior at the top level of the file (`hostname`, `action`,
//! `authentication`, `policies`, ...). The Rust line reads origin
//! behavior only from `origins.<hostname>:` and has never translated the
//! flat shape into it, so every one of those keys used to be dropped
//! with a single warning: the proxy booted with no origin at all,
//! answered 404 for the hostname the file declared, and `sbproxy
//! validate` called the same file valid. An operator who believed they
//! had authentication and IP allow-listing deployed with neither.
//!
//! `compile_config` now refuses a file carrying those keys, with a
//! message that names them and points at
//! <https://github.com/soapbucket/sbproxy-go> for anyone who wants to
//! keep running the Go config as written. The fixtures below are the
//! evidence: they came from
//! <https://github.com/soapbucket/sbproxy-go/tree/v0.1.2/tests/config-compat>
//! and are kept so the refusal is pinned against real legacy files
//! rather than against a document written to fail.
//!
//! Descriptive leftovers (`id`, `config_version`, `workspace_id`) are
//! not part of this and still only warn; a modern config carrying them
//! boots. That case is pinned in `compiler.rs`.

use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("v1-compat-fixtures")
}

/// The refusal lists the keys it dropped between this marker and the
/// first full stop after it.
///
/// Anchoring on a literal, rather than asking whether a key name appears
/// anywhere in the message, is what makes these assertions mean
/// something: the prose that follows the list mentions `hostname` twice
/// on its own account, so a whole-message `contains` would report a pass
/// for a key the refusal never listed.
const REFUSED_LIST_MARKER: &str = "carry origin behavior: ";

/// The exact set of behavior keys each archived fixture declares. The
/// refusal has to name all of them and nothing else: an operator reading
/// a partial list would move half a config and redeploy still open.
const EXPECTED_KEYS: &[(&str, &[&str])] = &[
    (
        "ai-gateway.yml",
        &[
            "action",
            "authentication",
            "hostname",
            "policies",
            "response_modifiers",
        ],
    ),
    ("basic-proxy.yml", &["action", "hostname"]),
    (
        "full-features.yml",
        &[
            "action",
            "allowed_methods",
            "authentication",
            "cors",
            "force_ssl",
            "forward_rules",
            "hostname",
            "policies",
            "request_modifiers",
            "response_modifiers",
            "session",
            "variables",
        ],
    ),
];

/// Pull the refused key list out of a refusal message.
///
/// Panics rather than falling back to the whole message when the marker
/// is missing: a reworded refusal has to redden loudly here, not degrade
/// into a weaker assertion that keeps passing.
fn refused_keys(message: &str) -> Vec<String> {
    let (_, tail) = message.split_once(REFUSED_LIST_MARKER).unwrap_or_else(|| {
        panic!("refusal does not carry the `{REFUSED_LIST_MARKER}` list marker: {message}")
    });
    let (list, _) = tail
        .split_once('.')
        .unwrap_or_else(|| panic!("refused key list is unterminated: {message}"));
    list.split(',')
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

#[test]
fn v1_fixtures_are_refused_with_the_go_deprecation() {
    let dir = fixtures_dir();
    assert!(
        dir.is_dir(),
        "fixture directory missing at {}",
        dir.display()
    );

    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {}", dir.display(), e))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yml"))
        .collect();
    files.sort();

    assert_eq!(
        files.len(),
        EXPECTED_KEYS.len(),
        "the fixture set changed; every fixture in {} must be listed in EXPECTED_KEYS",
        dir.display()
    );

    let mut failures = Vec::new();
    for file in &files {
        let name = file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let expected: Vec<String> = EXPECTED_KEYS
            .iter()
            .find(|(fixture, _)| *fixture == name)
            .map(|(_, keys)| keys.iter().map(|k| (*k).to_string()).collect())
            .unwrap_or_else(|| panic!("fixture {name} is not listed in EXPECTED_KEYS"));

        let yaml = match std::fs::read_to_string(file) {
            Ok(yaml) => yaml,
            Err(e) => {
                failures.push(format!("{name}: read failed: {e}"));
                continue;
            }
        };

        let Err(err) = sbproxy_config::compile_config(&yaml) else {
            failures.push(format!(
                "{name}: compiled clean. A flat Go v0.1.x file that compiles boots an empty \
                 proxy and answers 404 for the hostname it declares."
            ));
            continue;
        };
        let message = format!("{err:#}");

        let refused = refused_keys(&message);
        if refused != expected {
            failures.push(format!(
                "{name}: refusal lists {refused:?}, expected exactly {expected:?}"
            ));
        }
        if !message.contains("sbproxy-go") {
            failures.push(format!(
                "{name}: refusal does not point at `sbproxy-go` for operators who want to keep \
                 running the Go config: {message}"
            ));
        }
        if !message.contains("MIGRATION.md") {
            failures.push(format!(
                "{name}: refusal does not point at `MIGRATION.md` for the current shape: {message}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} archived v0.1.x fixtures were not refused with the deprecation:\n  {}",
        failures.len(),
        files.len(),
        failures.join("\n  ")
    );
}

/// The metadata half of the same files. `basic-proxy.yml` carries
/// `config_version`, `id`, `workspace_id`, and `version` alongside its
/// two behavior keys, and none of those four may reach the refused list:
/// dropping them changes nothing, so WOR-1140's warning is the right
/// answer for them and a modern config that still carries one has to
/// keep booting.
#[test]
fn the_refusal_names_only_the_behavior_keys_not_the_metadata() {
    let yaml = std::fs::read_to_string(fixtures_dir().join("basic-proxy.yml"))
        .expect("basic-proxy.yml is a checked-in fixture");
    let err = sbproxy_config::compile_config(&yaml)
        .err()
        .expect("a flat Go v0.1.x file is refused");

    let refused = refused_keys(&format!("{err:#}"));
    for metadata in ["config_version", "id", "workspace_id", "version"] {
        assert!(
            !refused.iter().any(|k| k == metadata),
            "`{metadata}` is descriptive, not behavior, and must not be refused: {refused:?}"
        );
    }
}

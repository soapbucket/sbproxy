//! Schema-compat regression test for v0.1.x Go `sb.yml` configs.
//!
//! MIGRATION.md promises that an existing `sb.yml` written for the
//! archived Go implementation continues to load on the Rust v1 line.
//! The source fixtures came from
//! <https://github.com/soapbucket/sbproxy-go/tree/v0.1.2/tests/config-compat>.
//! Every fixture in `tests/v1-compat-fixtures/` must compile against the
//! current schema **and** produce at least one origin for the hostname
//! the file declares. Compiling to an empty proxy is not compatibility.
//!
//! When a v1-style field is intentionally removed, this test fails
//! and the breaking change has to be called out in MIGRATION.md
//! before the test is updated.

use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("v1-compat-fixtures")
}

#[test]
fn v1_fixtures_compile_unmodified() {
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

    assert!(
        !files.is_empty(),
        "no v1-compat fixtures found in {}",
        dir.display()
    );

    let mut failures = Vec::new();
    for file in &files {
        let yaml = std::fs::read_to_string(file).unwrap_or_else(|e| {
            failures.push(format!("{}: read failed: {}", file.display(), e));
            String::new()
        });
        if yaml.is_empty() {
            continue;
        }
        match sbproxy_config::compile_config(&yaml) {
            Err(e) => {
                failures.push(format!("{}: compile_config: {}", file.display(), e));
            }
            Ok(compiled) => {
                if compiled.origins.is_empty() {
                    failures.push(format!(
                        "{}: compiled with zero origins (schema-v1 flat file was dropped)",
                        file.display()
                    ));
                    continue;
                }
                if let Some(hostname) = yaml_hostname(&yaml) {
                    let present = compiled
                        .host_map
                        .keys()
                        .any(|host| host.as_str() == hostname);
                    if !present {
                        failures.push(format!(
                            "{}: compiled origins do not include hostname `{hostname}`",
                            file.display()
                        ));
                    }
                }
            }
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} of {} v1-compat fixtures failed to compile on the v2 schema:\n  {}\n\nIf this is intentional, update MIGRATION.md with the breaking change before adjusting the fixtures.",
            failures.len(),
            files.len(),
            failures.join("\n  ")
        );
    }
}

fn yaml_hostname(yaml: &str) -> Option<&str> {
    for line in yaml.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("hostname:") {
            let value = rest.trim().trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

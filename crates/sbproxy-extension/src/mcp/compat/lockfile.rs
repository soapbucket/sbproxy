//! The lockfile baseline.
//!
//! `tool-versions.lock.yaml` is a committed snapshot of each tool's contract
//! digest and declared semver. The oracle diffs live tools against it and fails
//! the gate when a tool's contract changed without a matching semver bump,
//! the same shape as a `Cargo.lock` or a recorded contract: the baseline is
//! what "did this change" is measured against.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One tool's pinned identity in the lockfile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolLock {
    /// The tool's declared semantic version at snapshot time.
    pub semver: semver::Version,
    /// The `sha256:<hex>` contract digest captured for that version.
    pub contract_digest: String,
}

/// The committed baseline the oracle diffs live tools against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lockfile {
    /// Lockfile format version, so a reader can reject a future shape.
    pub version: u32,
    /// The server this baseline was generated for.
    pub generated_for: String,
    /// Per-tool pinned identity, keyed by tool name.
    pub tools: BTreeMap<String, ToolLock>,
}

impl Lockfile {
    /// Parse a lockfile from its YAML form.
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Render the lockfile to its YAML form.
    pub fn to_yaml(&self) -> anyhow::Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Lockfile {
        let mut tools = BTreeMap::new();
        tools.insert(
            "search_repos".to_string(),
            ToolLock {
                semver: semver::Version::new(2, 1, 0),
                contract_digest: "sha256:9e3a".to_string(),
            },
        );
        Lockfile {
            version: 1,
            generated_for: "test.sbproxy.dev".to_string(),
            tools,
        }
    }

    #[test]
    fn round_trips_through_yaml() {
        let lock = sample();
        let yaml = lock.to_yaml().expect("serialize");
        let back = Lockfile::from_yaml(&yaml).expect("parse");
        assert_eq!(lock, back);
    }

    #[test]
    fn parses_a_written_lockfile() {
        let yaml = "\
version: 1
generated_for: test.sbproxy.dev
tools:
  search_repos:
    semver: \"2.1.0\"
    contract_digest: \"sha256:9e3a\"
";
        let lock = Lockfile::from_yaml(yaml).expect("parse");
        assert_eq!(lock.version, 1);
        let tool = lock.tools.get("search_repos").expect("tool present");
        assert_eq!(tool.semver, semver::Version::new(2, 1, 0));
        assert_eq!(tool.contract_digest, "sha256:9e3a");
    }
}

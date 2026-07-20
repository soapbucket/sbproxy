use std::fs;
use std::io::Read;
use std::path::{Component, Path};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::parse_cases;

/// Provenance and checksum manifest for committed smoke inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Every committed input covered by this manifest.
    pub artifacts: Vec<FixtureArtifact>,
}

/// Trust metadata for one independently authored fixture file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureArtifact {
    /// Repository-relative path below the harness root.
    pub path: String,
    /// Corpus identifier expected in every normalized case.
    pub corpus: String,
    /// Closed first-party origin statement.
    pub provenance: String,
    /// License covering this independently authored fixture.
    pub license: String,
    /// Must remain false for committed smoke data.
    pub contains_customer_data: bool,
    /// Must remain false because smoke fixtures are not official scores.
    pub official_benchmark_score: bool,
    /// Lowercase SHA-256 digest of the exact fixture bytes.
    pub sha256: String,
}

/// Verified provenance attached to a detached evaluation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedProvenanceSummary {
    /// Lowercase SHA-256 digest of the exact provenance manifest bytes.
    pub manifest_sha256: String,
    /// Verified metadata for only the fixture inputs selected by this report.
    pub artifacts: Vec<FixtureArtifact>,
}

impl VerifiedProvenanceSummary {
    /// Build a stable summary after the caller verifies the manifest and selected inputs.
    pub fn from_verified_inputs(
        manifest_bytes: &[u8],
        mut artifacts: Vec<FixtureArtifact>,
    ) -> Self {
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        Self {
            manifest_sha256: sha256_hex(manifest_bytes),
            artifacts,
        }
    }
}

/// Parse a strict provenance manifest.
pub fn load_provenance(mut reader: impl Read) -> Result<ProvenanceManifest> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|error| anyhow!("parse provenance manifest: {error}"))
}

/// Verify path safety, provenance, checksums, corpus identity, and privacy.
pub fn verify_fixture_set(root: &Path, manifest: &ProvenanceManifest) -> Result<()> {
    if manifest.schema_version != 1 {
        bail!(
            "unsupported provenance schema version {}",
            manifest.schema_version
        );
    }
    if manifest.artifacts.is_empty() {
        bail!("provenance manifest must cover at least one fixture");
    }
    for artifact in &manifest.artifacts {
        let relative = Path::new(&artifact.path);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            bail!(
                "fixture path must be relative and contained: {}",
                artifact.path
            );
        }
        let first_party = matches!(
            artifact.provenance.as_str(),
            "independently_authored_synthetic" | "independently_authored_sanitized_shape"
        );
        let operator_supplied = artifact.provenance == "operator_supplied_external";
        if !first_party && !operator_supplied {
            bail!("fixture provenance is not recognized: {}", artifact.path);
        }
        if first_party && artifact.license != "Apache-2.0" {
            bail!("fixture license must be Apache-2.0: {}", artifact.path);
        }
        if operator_supplied && artifact.license.trim().is_empty() {
            bail!(
                "operator-supplied fixture must declare its license: {}",
                artifact.path
            );
        }
        if artifact.contains_customer_data {
            bail!("fixture claims customer data: {}", artifact.path);
        }
        if artifact.official_benchmark_score {
            bail!(
                "fixture claims an official benchmark score: {}",
                artifact.path
            );
        }

        let bytes = fs::read(root.join(relative))
            .with_context(|| format!("read fixture {}", artifact.path))?;
        let actual = sha256_hex(&bytes);
        if actual != artifact.sha256 {
            bail!(
                "fixture checksum mismatch for {}: expected {}, got {}",
                artifact.path,
                artifact.sha256,
                actual
            );
        }
        validate_privacy(&artifact.path, &bytes)?;
        let cases = parse_cases(bytes.as_slice())?;
        if cases.is_empty() {
            bail!("fixture has no cases: {}", artifact.path);
        }
        if let Some(case) = cases.iter().find(|case| case.corpus != artifact.corpus) {
            bail!(
                "fixture {} contains corpus {} instead of {}",
                artifact.path,
                case.corpus,
                artifact.corpus
            );
        }
    }
    Ok(())
}

fn validate_privacy(path: &str, bytes: &[u8]) -> Result<()> {
    let text = String::from_utf8_lossy(bytes);
    let lowercase = text.to_ascii_lowercase();
    const FORBIDDEN: &[&str] = &[
        "authorization:",
        "bearer ",
        "api_key",
        "api-key",
        "sk-",
        "begin private key",
        "/users/",
        "/home/",
        "c:\\users\\",
        "redis://",
        "customer prompt",
    ];
    if let Some(pattern) = FORBIDDEN
        .iter()
        .find(|pattern| lowercase.contains(**pattern))
    {
        bail!("fixture privacy check failed for {path}: forbidden pattern `{pattern}`");
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

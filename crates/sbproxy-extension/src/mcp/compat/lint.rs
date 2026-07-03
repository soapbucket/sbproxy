//! The version-bump linter: does the declared bump match the computed grade?
//!
//! The MCP analog of `cargo-semver-checks` or `elm diff`: given the prior
//! version, the newly declared version, and the compatibility verdict, it flags
//! an under-bump (a breaking change shipped as a patch) or an unchanged version
//! over a changed contract (the "behavior must not change without a version
//! increment" invariant). Over-bumping is allowed.

use super::{CompatibilityVerdict, SemverGrade};
use semver::Version;

/// Result of linting a declared version bump.
#[derive(Debug, Clone, PartialEq)]
pub enum BumpVerdict {
    /// The declared bump is at least as large as the computed grade requires.
    Ok,
    /// The declared bump is smaller than the change requires.
    Violation {
        /// The prior version (from the lockfile baseline).
        prior: Version,
        /// The newly declared version (from the registry).
        declared: Version,
        /// The grade the oracle computed.
        computed: SemverGrade,
        /// Human-readable explanation.
        detail: String,
    },
}

/// Lint the declared bump against the computed compatibility grade.
pub fn lint_bump(
    prior: &Version,
    declared: &Version,
    verdict: &CompatibilityVerdict,
) -> BumpVerdict {
    let declared_bump = bump_kind(prior, declared);
    let required = verdict.grade;
    if declared_bump >= required {
        return BumpVerdict::Ok;
    }
    let detail = format!(
        "tool `{}` needs a {} bump but {prior} to {declared} is only a {}",
        verdict.tool,
        grade_word(required),
        grade_word(declared_bump),
    );
    BumpVerdict::Violation {
        prior: prior.clone(),
        declared: declared.clone(),
        computed: required,
        detail,
    }
}

/// Classify the version delta as the semver grade it represents. A downgrade
/// or unchanged version is [`SemverGrade::None`].
fn bump_kind(prior: &Version, declared: &Version) -> SemverGrade {
    if declared.major > prior.major {
        SemverGrade::Major
    } else if declared.major == prior.major && declared.minor > prior.minor {
        SemverGrade::Minor
    } else if declared.major == prior.major
        && declared.minor == prior.minor
        && declared.patch > prior.patch
    {
        SemverGrade::Patch
    } else {
        SemverGrade::None
    }
}

fn grade_word(grade: SemverGrade) -> &'static str {
    match grade {
        SemverGrade::None => "no",
        SemverGrade::Patch => "patch",
        SemverGrade::Minor => "minor",
        SemverGrade::Major => "major",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(grade: SemverGrade) -> CompatibilityVerdict {
        CompatibilityVerdict {
            tool: "t".into(),
            from_digest: "sha256:a".into(),
            to_digest: "sha256:b".into(),
            grade,
            findings: Vec::new(),
            behavioral_evaluated: false,
            needs_confirmation: false,
        }
    }

    #[test]
    fn major_change_with_major_bump_is_ok() {
        let v = verdict(SemverGrade::Major);
        assert_eq!(
            lint_bump(&Version::new(1, 4, 2), &Version::new(2, 0, 0), &v),
            BumpVerdict::Ok
        );
    }

    #[test]
    fn major_change_shipped_as_patch_is_violation() {
        let v = verdict(SemverGrade::Major);
        let out = lint_bump(&Version::new(1, 4, 2), &Version::new(1, 4, 3), &v);
        assert!(matches!(
            out,
            BumpVerdict::Violation {
                computed: SemverGrade::Major,
                ..
            }
        ));
    }

    #[test]
    fn changed_contract_with_no_bump_is_violation() {
        let v = verdict(SemverGrade::Patch);
        let out = lint_bump(&Version::new(1, 0, 0), &Version::new(1, 0, 0), &v);
        assert!(matches!(out, BumpVerdict::Violation { .. }));
    }

    #[test]
    fn no_change_no_bump_is_ok() {
        let v = verdict(SemverGrade::None);
        assert_eq!(
            lint_bump(&Version::new(1, 0, 0), &Version::new(1, 0, 0), &v),
            BumpVerdict::Ok
        );
    }
}

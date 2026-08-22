//! CEL inline-predicate bridge.
//!
//! CEL is a dependent surface of the Cedar primary path here: a CEL
//! expression attached to a Cedar policy is evaluated by the host
//! (this bridge) and the resulting boolean feeds back into Cedar via
//! a condition wrapper. CEL is NOT a peer authoring surface; a policy
//! author never writes "a CEL policy" in this engine.
//!
//! This ships the type and the evaluation entry point as a stub that
//! always returns `Ok(true)`. The dependent surface is in place so a
//! follow-up can wire real evaluation without re-shaping the call
//! sites; the Cedar evaluator does not call this bridge yet.
//!
//! The eventual CEL backend is sbproxy's own [`crate::cel`] engine,
//! which already wraps the `cel` crate for CEL expression evaluation
//! elsewhere in this crate (routing, access control, header
//! matching). Migrating [`CelPredicate::evaluate`] from the stub to
//! [`crate::cel::CelExpression`] is a mechanical change inside this
//! module; the public API here does not need to change.

use thiserror::Error;

/// Errors raised by the CEL bridge.
///
/// The variants are placeholders for the live evaluation integration:
/// a parse error from the CEL grammar, a type error from the CEL type
/// checker, and a runtime error from the expression evaluator. The
/// stub in this module does not raise any of these; defining the
/// variants up front pins a caller's fail-closed mapping (any
/// `CelBridgeError` should become a structured Deny with a
/// fail-closed reason string once live evaluation lands).
#[derive(Debug, Error)]
pub enum CelBridgeError {
    /// CEL source text failed to parse. Reserved for the live
    /// evaluation integration.
    #[error("cel parse error: {0}")]
    Parse(String),

    /// CEL expression failed type checking against the supplied
    /// activation. Reserved for the live evaluation integration.
    #[error("cel type error: {0}")]
    Type(String),

    /// CEL expression raised a runtime error during evaluation
    /// (division by zero, missing field, etc.). Reserved for the live
    /// evaluation integration.
    #[error("cel evaluation error: {0}")]
    Evaluation(String),
}

/// A CEL inline predicate attached to a Cedar policy.
///
/// This stores the source text and exposes a single
/// [`CelPredicate::evaluate`] entry point. Wiring [`crate::cel`] in
/// will pre-compile the source at construction time (the parse +
/// type-check happens once per policy-set compile) and stash the
/// compiled program on this struct; the public API does not need to
/// change.
#[derive(Debug, Clone)]
pub struct CelPredicate {
    source: String,
}

impl CelPredicate {
    /// Construct a predicate from the source text.
    ///
    /// The source is stored verbatim today. Wiring [`crate::cel`] in
    /// will move the parse + type-check here so a malformed predicate
    /// fails the policy-set compile path rather than the request hot
    /// path. The signature already returns `Result` so that upgrade
    /// is non-breaking.
    pub fn new(source: impl Into<String>) -> Result<Self, CelBridgeError> {
        Ok(Self {
            source: source.into(),
        })
    }

    /// Source text the predicate was constructed with. Useful for an
    /// audit trail (a verdict event can include the predicate source
    /// so a verifier can reproduce the boolean) and for a policy diff
    /// render.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Evaluate the predicate.
    ///
    /// Returns `Ok(true)` unconditionally today; the dependent
    /// surface is in place so live evaluation can land without
    /// re-shaping call sites.
    ///
    /// A future extension will take an activation map (request
    /// attributes, principal attributes, resource attributes, helper
    /// outputs) and route through [`crate::cel::CelExpression`]. The
    /// `Result` shape is already in place so that upgrade is
    /// non-breaking.
    pub fn evaluate(&self) -> Result<bool, CelBridgeError> {
        // Stub: always true. Source text is stashed so the upgrade
        // path can call into the live evaluator without re-shaping
        // the call site.
        let _ = &self.source;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stub returns `Ok(true)` and preserves the source text.
    #[test]
    fn stub_evaluate_returns_true() {
        let pred = CelPredicate::new("request.method == 'GET'").expect("new");
        assert!(pred.evaluate().unwrap());
        assert_eq!(pred.source(), "request.method == 'GET'");
    }
}

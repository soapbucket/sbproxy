//! Scorer adapters that keep the request path behind one trait object.
//!
//! The rule-pack loader, the in-process ONNX model, and the future
//! sidecar scorer all implement [`AgentScorer`].
//! Core code installs one process-wide scorer and the hot path calls
//! only that trait, so adding a new backend does not change request
//! handling.

use std::sync::Arc;

use crate::{AgentDetection, AgentProvenance, AgentScorer, DefaultScorer, RulePackLoader, Signals};

/// Scorer backed by a hot-reloading [`RulePackLoader`].
///
/// Unlike [`crate::rules::RulePackScorer`], this adapter reads through
/// the loader on every request so same-path reloads take effect without
/// rebuilding the outer scorer object.
#[derive(Clone)]
pub struct RulePackLoaderScorer {
    loader: Arc<RulePackLoader>,
}

impl RulePackLoaderScorer {
    /// Wrap a shared rule-pack loader as an [`AgentScorer`].
    pub fn new(loader: Arc<RulePackLoader>) -> Self {
        Self { loader }
    }

    /// Borrow the underlying loader for tests and reload plumbing.
    pub fn loader(&self) -> &Arc<RulePackLoader> {
        &self.loader
    }
}

impl AgentScorer for RulePackLoaderScorer {
    fn score(&self, signals: &Signals) -> AgentDetection {
        if let Some(detection) = self.loader.pack().evaluate(signals) {
            return detection;
        }
        DefaultScorer.score(signals)
    }
}

/// Chains two scorers, using the fallback only when the primary returns
/// the neutral unsigned-anonymous score.
///
/// This lets operators keep exact rule-pack identities ahead of the
/// probabilistic model while still getting an ONNX score on rule misses.
#[derive(Clone)]
pub struct FallbackAgentScorer {
    primary: Arc<dyn AgentScorer>,
    fallback: Arc<dyn AgentScorer>,
}

impl FallbackAgentScorer {
    /// Build a primary/fallback scorer chain.
    pub fn new(primary: Arc<dyn AgentScorer>, fallback: Arc<dyn AgentScorer>) -> Self {
        Self { primary, fallback }
    }
}

impl AgentScorer for FallbackAgentScorer {
    fn score(&self, signals: &Signals) -> AgentDetection {
        let detection = self.primary.score(signals);
        if is_neutral_unsigned_anonymous(&detection) {
            self.fallback.score(signals)
        } else {
            detection
        }
    }
}

fn is_neutral_unsigned_anonymous(detection: &AgentDetection) -> bool {
    detection.score == 0
        && detection.agent_id.is_none()
        && detection.provenance == AgentProvenance::UnsignedAnonymous
        && detection.confidence == 0.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{AgentRule, CompiledRulePack, MatchSpec, RulePack, ADRF_VERSION};
    use crate::{AgentProvenance, HttpSignals, Signals};

    #[derive(Clone)]
    struct FixedScorer(AgentDetection);

    impl AgentScorer for FixedScorer {
        fn score(&self, _signals: &Signals) -> AgentDetection {
            self.0.clone()
        }
    }

    #[test]
    fn rule_pack_loader_scorer_reads_current_pack() {
        let pack = CompiledRulePack::compile(RulePack {
            version: ADRF_VERSION,
            agents: vec![AgentRule {
                id: "codex-cli".to_string(),
                r#match: MatchSpec {
                    user_agent_pattern: Some("^codex/".to_string()),
                    ..MatchSpec::default()
                },
                provenance: AgentProvenance::UnsignedNamed,
                score: 91,
                confidence: 0.87,
            }],
        })
        .expect("pack compiles");
        let loader = Arc::new(RulePackLoader::from_pack(pack, "/nonexistent/agents.yml"));
        let scorer = RulePackLoaderScorer::new(loader);
        let detection = scorer.score(&Signals {
            http: Some(HttpSignals {
                user_agent: Some("codex/1.2.3".to_string()),
                ..HttpSignals::default()
            }),
            ..Signals::default()
        });

        assert_eq!(detection.agent_id.as_deref(), Some("codex-cli"));
        assert_eq!(detection.score, 91);
    }

    #[test]
    fn fallback_scorer_uses_fallback_on_neutral_primary() {
        let primary: Arc<dyn AgentScorer> = Arc::new(FixedScorer(AgentDetection::unscored()));
        let fallback: Arc<dyn AgentScorer> = Arc::new(FixedScorer(AgentDetection {
            score: 73,
            agent_id: None,
            provenance: AgentProvenance::UnsignedAnonymous,
            confidence: 0.73,
            signals_used: vec!["onnx_catboost".to_string()],
            headless_score: 0,
            headless_indicators: Vec::new(),
        }));
        let detection = FallbackAgentScorer::new(primary, fallback).score(&Signals::default());

        assert_eq!(detection.score, 73);
        assert_eq!(detection.signals_used, vec!["onnx_catboost"]);
    }

    #[test]
    fn fallback_scorer_keeps_named_primary_match() {
        let primary: Arc<dyn AgentScorer> = Arc::new(FixedScorer(AgentDetection {
            score: 95,
            agent_id: Some("claude-code-cli".to_string()),
            provenance: AgentProvenance::UnsignedNamed,
            confidence: 0.95,
            signals_used: vec!["user_agent_pattern".to_string()],
            headless_score: 0,
            headless_indicators: Vec::new(),
        }));
        let fallback: Arc<dyn AgentScorer> = Arc::new(FixedScorer(AgentDetection {
            score: 40,
            agent_id: None,
            provenance: AgentProvenance::UnsignedAnonymous,
            confidence: 0.4,
            signals_used: vec!["onnx_catboost".to_string()],
            headless_score: 0,
            headless_indicators: Vec::new(),
        }));
        let detection = FallbackAgentScorer::new(primary, fallback).score(&Signals::default());

        assert_eq!(detection.agent_id.as_deref(), Some("claude-code-cli"));
        assert_eq!(detection.score, 95);
    }
}

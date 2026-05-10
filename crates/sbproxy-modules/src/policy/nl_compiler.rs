//! Natural-language to Cedar policy compiler (WOR-203 PR 3b).
//!
//! Wraps the [`NlLinter`](crate::policy::nl_linter::NlLinter) (PR 3a) and the
//! [`JudgeClient`](sbproxy_ai::judge::JudgeClient) (WOR-202) into a
//! single async entry point. The flow follows
//! `adr-policy-compilation.md` (NLC pillars A and B):
//!
//! 1. Run the linter; refuse to compile when the rule set fires.
//! 2. Build a fixed compilation prompt that pins the Cedar grammar
//!    plus the workspace schema, and ask the judge to translate the
//!    NL input.
//! 3. Hash the returned Cedar source and pack the result into a
//!    [`CompiledPolicy`] candidate. The caller pins it after author
//!    acknowledgement (per the ADR's pillar C contract).
//!
//! ## Judge contract for compilation
//!
//! The judge backend is provider-agnostic. The compiler interprets
//! its verdict as follows:
//!
//! | Verdict | Meaning |
//! |---|---|
//! | [`PolicyDecision::Allow`](sbproxy_plugin::PolicyDecision::Allow) | Compilation succeeded but the judge attached no Cedar; the compiler rejects this as [`NlCompileError::MalformedOutput`] because there is no Cedar source to pin. |
//! | [`PolicyDecision::AllowWithHeaders`](sbproxy_plugin::PolicyDecision::AllowWithHeaders) | Compilation succeeded; the Cedar source lives in the `cedar_source` header value. |
//! | [`PolicyDecision::Deny`](sbproxy_plugin::PolicyDecision::Deny) | Compilation refused; the `message` field carries the refusal reason. Returned as [`NlCompileError::MalformedOutput`] with the reason inlined so the caller can surface it to the author. |
//! | [`PolicyDecision::Confirm`](sbproxy_plugin::PolicyDecision::Confirm) | Treated as [`NlCompileError::MalformedOutput`]: the compiler use-case has no notion of a held-pending verdict. |
//!
//! The judge backend in this OSS slice is a single-provider chat
//! endpoint. A provider that conforms to the existing
//! [`JudgeClient`](sbproxy_ai::judge::JudgeClient) response contract
//! (`{verdict: "allow" | "deny", ...}`) returning `cedar_source`
//! either as a top-level field or inside the `headers` array under
//! the name `cedar_source` is the shape the compiler expects.

use std::sync::Arc;

use chrono::Utc;
use sbproxy_ai::judge::{JudgeClient, JudgeError};
use sbproxy_plugin::PolicyDecision;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::compiled_policy_store::CompiledPolicy;
use super::nl_linter::{LintViolation, NlLinter, WorkspaceSchema};

/// Compiler facade owning a [`JudgeClient`] and a versioned prompt.
///
/// Cheap to clone (only `Arc<JudgeClient>` and a small string). Build
/// one per process at startup; pass clones into the request paths or
/// admin handlers that need to compile NL policies.
#[derive(Clone)]
pub struct NlCompiler {
    judge: Arc<JudgeClient>,
    compiler_version: String,
}

/// Failure modes the compiler surfaces to its caller.
///
/// `LintFailed` is the common author-error path; the inner list is
/// every rule the linter caught so the author can fix everything in
/// one round-trip. `JudgeError` wraps the upstream judge failure for
/// transparency; `MalformedOutput` is the catch-all when the judge
/// produced a verdict shape the compiler did not know how to read.
#[derive(Debug, thiserror::Error)]
pub enum NlCompileError {
    /// The pre-compilation linter caught one or more violations.
    /// Contains every violation the linter found in a single pass.
    #[error("nl input failed lint ({} violations)", .0.len())]
    LintFailed(Vec<LintViolation>),
    /// The judge backend returned an error or could not be reached.
    #[error("judge error: {0}")]
    JudgeError(#[from] JudgeError),
    /// The judge returned a 2xx verdict shape the compiler could not
    /// interpret as a Cedar policy. The inner string is suitable for
    /// logging but not for returning verbatim to untrusted clients.
    #[error("malformed compiler output: {0}")]
    MalformedOutput(String),
}

/// Header name the compiler reads for the Cedar source on an
/// [`AllowWithHeaders`](sbproxy_plugin::PolicyDecision::AllowWithHeaders)
/// verdict.
const CEDAR_SOURCE_HEADER: &str = "cedar_source";

impl NlCompiler {
    /// Build a new compiler.
    ///
    /// `compiler_version` is a semver-shaped string identifying the
    /// prompt version that produced the compiled Cedar. Any change to
    /// the compilation prompt or the underlying provider model that
    /// can shift the output distribution must bump this string so the
    /// drift detector in pillar C can see compiler upgrades.
    pub fn new(judge: Arc<JudgeClient>, compiler_version: impl Into<String>) -> Self {
        Self {
            judge,
            compiler_version: compiler_version.into(),
        }
    }

    /// The compiler version this instance is pinned to.
    pub fn compiler_version(&self) -> &str {
        &self.compiler_version
    }

    /// Compile `nl` against `schema` and return a candidate
    /// [`CompiledPolicy`].
    ///
    /// Returns:
    ///
    /// - `Err(NlCompileError::LintFailed(_))` when the linter caught
    ///   violations. The caller surfaces these to the author and does
    ///   not call the judge.
    /// - `Err(NlCompileError::JudgeError(_))` when the judge backend
    ///   itself errored (budget, transport, malformed transport-level
    ///   response). The caller decides whether to retry.
    /// - `Err(NlCompileError::MalformedOutput(_))` when the judge
    ///   returned a 2xx verdict that the compiler could not turn into
    ///   a Cedar source.
    /// - `Ok(CompiledPolicy)` on success. The candidate carries
    ///   `pinned_by = "system"`; the caller overwrites this with the
    ///   author's subject identifier before persisting via
    ///   [`CompiledPolicyStore::insert`](crate::policy::compiled_policy_store::CompiledPolicyStore::insert).
    ///
    /// The candidate's `pinned_at` is the wall-clock at compile time.
    /// Callers that need to attribute the pin to a different moment
    /// (e.g. async author acknowledgement) overwrite the field before
    /// inserting into the store.
    pub async fn compile(
        &self,
        nl: &str,
        schema: &WorkspaceSchema,
    ) -> Result<CompiledPolicy, NlCompileError> {
        // --- Pillar A: lint first; never burn a judge call on input
        // the linter would have caught.
        let violations = NlLinter::lint(nl, schema);
        if !violations.is_empty() {
            return Err(NlCompileError::LintFailed(violations));
        }

        // --- Pillar B: prompt the judge.
        let prompt = build_compilation_prompt(&self.compiler_version, schema);
        let payload = serde_json::json!({
            "task": "nl_to_cedar",
            "nl": nl,
            "schema": serialise_schema(schema),
            "compiler_version": &self.compiler_version,
        });

        let verdict = self.judge.semantic(&prompt, payload).await?;
        let cedar_source = interpret_verdict(verdict)?;

        // --- Pillar C: hash + pack.
        let content_hash = sha256_hex(&cedar_source);
        Ok(CompiledPolicy {
            policy_id: Uuid::new_v4(),
            nl_source: nl.to_string(),
            cedar_source,
            compiler_version: self.compiler_version.clone(),
            content_hash,
            pinned_at: Utc::now(),
            pinned_by: "system".to_string(),
        })
    }
}

/// Translate a [`PolicyDecision`] into the compiled Cedar source per
/// the contract documented in the module rustdoc.
fn interpret_verdict(verdict: PolicyDecision) -> Result<String, NlCompileError> {
    match verdict {
        PolicyDecision::AllowWithHeaders { headers } => headers
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(CEDAR_SOURCE_HEADER))
            .map(|(_, value)| value)
            .ok_or_else(|| {
                NlCompileError::MalformedOutput(format!(
                    "judge Allow verdict missing '{CEDAR_SOURCE_HEADER}' header"
                ))
            }),
        PolicyDecision::Allow => Err(NlCompileError::MalformedOutput(
            "judge returned bare Allow with no Cedar source attached".to_string(),
        )),
        PolicyDecision::Deny { message, .. } => Err(NlCompileError::MalformedOutput(format!(
            "judge refused compilation: {message}"
        ))),
        PolicyDecision::Confirm { reason, .. } => Err(NlCompileError::MalformedOutput(format!(
            "judge returned Confirm verdict, which the compiler does not handle: {reason}"
        ))),
    }
}

/// Build the system prompt the judge sees.
///
/// Deterministic by construction: the only inputs are the
/// `compiler_version` and the workspace schema. The prompt is small
/// and human-readable so operators can reason about what the LLM is
/// asked to do without diving into the crate.
fn build_compilation_prompt(version: &str, schema: &WorkspaceSchema) -> String {
    let mut prompt = String::new();
    prompt.push_str("You are an NL-to-Cedar policy compiler. Version: ");
    prompt.push_str(version);
    prompt.push_str(".\n\n");
    prompt
        .push_str("Translate the user's natural-language constraint into a single Cedar policy. ");
    prompt
        .push_str("Use only the principal types, resource types, action groups, and model names ");
    prompt.push_str("listed in the schema. Reject inputs that reference unknown identifiers.\n\n");
    prompt.push_str("Workspace schema:\n");
    prompt.push_str(&format!(
        "  principal_types: {:?}\n",
        schema.principal_types
    ));
    prompt.push_str(&format!("  resource_types:  {:?}\n", schema.resource_types));
    prompt.push_str(&format!("  action_groups:   {:?}\n", schema.action_groups));
    prompt.push_str(&format!("  model_names:     {:?}\n", schema.model_names));
    prompt.push_str("\nResponse contract:\n");
    prompt.push_str("- On success, reply with verdict=\"allow\" and a header named \"cedar_source\" carrying the Cedar policy text.\n");
    prompt.push_str("- On refusal, reply with verdict=\"deny\" and a message explaining why.\n");
    prompt
}

fn serialise_schema(schema: &WorkspaceSchema) -> serde_json::Value {
    serde_json::json!({
        "principal_types": schema.principal_types,
        "resource_types":  schema.resource_types,
        "action_groups":   schema.action_groups,
        "model_names":     schema.model_names,
    })
}

/// Hex-encoded SHA-256, prefixed with `sha256:` to match the format
/// used elsewhere in the workspace and the
/// `adr-policy-compilation.md` schema.
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_ai::judge::BudgetTracker;
    use sbproxy_ai::judge::{JudgeCache, JudgeClient, JudgeConfig};
    use std::sync::Arc;

    fn schema() -> WorkspaceSchema {
        WorkspaceSchema {
            principal_types: vec!["User".to_string(), "Agent".to_string()],
            resource_types: vec!["Invoice".to_string(), "Tool".to_string()],
            action_groups: vec!["read".to_string(), "write".to_string()],
            model_names: vec!["gpt-4o".to_string()],
        }
    }

    /// Build a `JudgeClient` whose cache is pre-loaded with the
    /// given verdict for whatever prompt + payload the compiler
    /// produces. The endpoint points at a closed port so a cache
    /// miss would surface as a transport error.
    async fn primed_judge(
        nl: &str,
        schema: &WorkspaceSchema,
        compiler_version: &str,
        verdict: PolicyDecision,
    ) -> Arc<JudgeClient> {
        // Allocate-and-drop a port to get an unused address.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let cfg = JudgeConfig {
            endpoint,
            api_key_env: "SBPROXY_NLC_TEST_KEY".to_string(),
            timeout_ms: 1_500,
            cache_capacity: 16,
            budget_tokens: 100,
        };
        let cache = Arc::new(JudgeCache::new(cfg.cache_capacity));
        let budget = Arc::new(BudgetTracker::new(cfg.budget_tokens));
        let client = Arc::new(JudgeClient::with_components(
            cfg,
            cache.clone(),
            budget,
            String::new(),
        ));
        let prompt = build_compilation_prompt(compiler_version, schema);
        let payload = serde_json::json!({
            "task": "nl_to_cedar",
            "nl": nl,
            "schema": serialise_schema(schema),
            "compiler_version": compiler_version,
        });
        let key = sbproxy_ai::judge::cache::cache_key(&prompt, &payload);
        cache.put(key, verdict);
        client
    }

    #[tokio::test]
    async fn linter_violation_blocks_compilation() {
        // The cache loader doesn't matter here; the linter fires
        // before any judge call. The bare predicate trips L009.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).unwrap();
        let cfg = JudgeConfig {
            endpoint,
            api_key_env: "SBPROXY_NLC_TEST_KEY".to_string(),
            timeout_ms: 1_500,
            cache_capacity: 16,
            budget_tokens: 100,
        };
        let client = Arc::new(JudgeClient::new(cfg));
        let compiler = NlCompiler::new(client, "1.0.0");

        let err = compiler
            .compile("everything is fine here", &schema())
            .await
            .expect_err("bare predicate must fail lint");
        match err {
            NlCompileError::LintFailed(violations) => {
                assert!(
                    violations.iter().any(|v| v.rule == "L009"),
                    "expected L009, got {violations:?}"
                );
            }
            other => panic!("expected LintFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn clean_input_produces_compiled_policy_with_content_hash() {
        let nl = "allow User to read Invoice";
        let schema = schema();
        let cedar = "permit(principal in User, action == Action::\"read\", resource is Invoice);";
        let verdict = PolicyDecision::AllowWithHeaders {
            headers: vec![(CEDAR_SOURCE_HEADER.to_string(), cedar.to_string())],
        };
        let judge = primed_judge(nl, &schema, "1.0.0", verdict).await;
        let compiler = NlCompiler::new(judge, "1.0.0");

        let policy = compiler
            .compile(nl, &schema)
            .await
            .expect("clean input compiles");
        assert_eq!(policy.nl_source, nl);
        assert_eq!(policy.cedar_source, cedar);
        assert_eq!(policy.compiler_version, "1.0.0");
        assert!(
            policy.content_hash.starts_with("sha256:"),
            "hash format: {}",
            policy.content_hash
        );
        assert_eq!(
            policy.content_hash.len(),
            "sha256:".len() + 64,
            "hex sha-256 width"
        );
        assert_eq!(policy.pinned_by, "system");
    }

    #[tokio::test]
    async fn deterministic_hash_for_same_cedar_output() {
        let nl = "allow User to read Invoice";
        let schema = schema();
        let cedar = "permit(principal in User, action == Action::\"read\", resource is Invoice);";
        let verdict = PolicyDecision::AllowWithHeaders {
            headers: vec![(CEDAR_SOURCE_HEADER.to_string(), cedar.to_string())],
        };
        let judge = primed_judge(nl, &schema, "1.0.0", verdict).await;
        let compiler = NlCompiler::new(judge, "1.0.0");

        let first = compiler.compile(nl, &schema).await.expect("first compile");
        let second = compiler.compile(nl, &schema).await.expect("second compile");
        assert_eq!(
            first.content_hash, second.content_hash,
            "same Cedar output must hash identically"
        );
        // The policy_id is a fresh UUID per compile call by design.
        assert_ne!(
            first.policy_id, second.policy_id,
            "every compilation must mint a new policy_id"
        );
    }

    #[tokio::test]
    async fn judge_deny_surfaces_as_malformed_output() {
        let nl = "allow User to read Invoice";
        let schema = schema();
        let verdict = PolicyDecision::Deny {
            status: 422,
            message: "schema is missing required types".to_string(),
        };
        let judge = primed_judge(nl, &schema, "1.0.0", verdict).await;
        let compiler = NlCompiler::new(judge, "1.0.0");

        let err = compiler
            .compile(nl, &schema)
            .await
            .expect_err("judge refusal must surface");
        match err {
            NlCompileError::MalformedOutput(msg) => {
                assert!(
                    msg.contains("schema is missing required types"),
                    "message must inline judge reason: {msg}"
                );
            }
            other => panic!("expected MalformedOutput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn judge_bare_allow_rejects_with_missing_header() {
        let nl = "allow User to read Invoice";
        let schema = schema();
        let judge = primed_judge(nl, &schema, "1.0.0", PolicyDecision::Allow).await;
        let compiler = NlCompiler::new(judge, "1.0.0");

        let err = compiler
            .compile(nl, &schema)
            .await
            .expect_err("bare Allow must fail");
        assert!(matches!(err, NlCompileError::MalformedOutput(_)));
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // Sanity check on the hashing helper. Vector is the
        // canonical SHA-256("abc").
        let h = sha256_hex("abc");
        assert_eq!(
            h,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

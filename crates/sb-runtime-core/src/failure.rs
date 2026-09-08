// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Stable engine failure taxonomy exposed by jobs and status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineFailureReason {
    /// Host policy blocks the requested action.
    EngineBlocked,
    /// Engine, artifact, or worker capabilities are incompatible.
    EngineIncompatible,
    /// Engine provisioning failed.
    EngineProvisionFailed,
    /// The local artifact is missing or not verified.
    ArtifactNotReady,
    /// An operator argument attempts to override a runtime-owned field.
    UnsafeArgument,
    /// The process could not be spawned.
    EngineSpawnFailed,
    /// The process exited before becoming ready.
    EngineEarlyExit,
    /// The readiness deadline elapsed.
    EngineReadinessTimeout,
    /// A live health check failed.
    EngineHealthFailed,
    /// Graceful and forced shutdown failed.
    EngineShutdownFailed,
    /// The bounded launch retry budget is exhausted until explicit reset.
    CrashLoop,
    /// Internal invariant or clock failure.
    EngineInternal,
}

impl EngineFailureReason {
    /// Stable snake-case reason code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EngineBlocked => "engine_blocked",
            Self::EngineIncompatible => "engine_incompatible",
            Self::EngineProvisionFailed => "engine_provision_failed",
            Self::ArtifactNotReady => "artifact_not_ready",
            Self::UnsafeArgument => "unsafe_argument",
            Self::EngineSpawnFailed => "engine_spawn_failed",
            Self::EngineEarlyExit => "engine_early_exit",
            Self::EngineReadinessTimeout => "engine_readiness_timeout",
            Self::EngineHealthFailed => "engine_health_failed",
            Self::EngineShutdownFailed => "engine_shutdown_failed",
            Self::CrashLoop => "crash_loop",
            Self::EngineInternal => "engine_internal",
        }
    }
}

impl fmt::Display for EngineFailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Operator-safe managed-engine failure with required remediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineDriverError {
    reason: EngineFailureReason,
    message: String,
    remediation: String,
    retryable: bool,
    diagnostic_tail: Option<String>,
}

impl EngineDriverError {
    /// Construct a typed error. Empty remediation is replaced with a safe fallback.
    pub fn new(
        reason: EngineFailureReason,
        message: impl Into<String>,
        remediation: impl Into<String>,
        retryable: bool,
    ) -> Self {
        let message = bounded_operator_text(&message.into(), 2_048);
        let remediation = bounded_operator_text(&remediation.into(), 1_024);
        Self {
            reason,
            message: if message.trim().is_empty() {
                "managed engine operation failed".to_string()
            } else {
                message
            },
            remediation: if remediation.trim().is_empty() {
                "inspect the model-host operation job and retry after correcting the cause"
                    .to_string()
            } else {
                remediation
            },
            retryable,
            diagnostic_tail: None,
        }
    }

    /// Construct a policy-blocked failure.
    pub fn blocked(message: impl Into<String>, remediation: impl Into<String>) -> Self {
        Self::new(
            EngineFailureReason::EngineBlocked,
            message,
            remediation,
            false,
        )
    }

    /// Construct an artifact-verification failure.
    pub fn artifact_not_ready(message: impl Into<String>) -> Self {
        Self::new(
            EngineFailureReason::ArtifactNotReady,
            message,
            "pull and verify the exact catalog artifact before launching the deployment",
            false,
        )
    }

    /// Construct a rejected argument failure.
    pub fn unsafe_argument(message: impl Into<String>) -> Self {
        Self::new(
            EngineFailureReason::UnsafeArgument,
            message,
            "remove the argument and use the typed model-host configuration field instead",
            false,
        )
    }

    /// Stable reason code.
    pub const fn reason(&self) -> EngineFailureReason {
        self.reason
    }

    /// Operator action that can resolve the failure.
    pub fn remediation(&self) -> &str {
        &self.remediation
    }

    /// Whether bounded retry can succeed without changing desired state.
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Concise operator-safe failure message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Attach a bounded, credential-redacted diagnostic tail.
    pub fn with_diagnostic_tail(mut self, diagnostic: impl AsRef<str>) -> Self {
        let diagnostic = sanitize_diagnostic_tail(diagnostic.as_ref());
        self.diagnostic_tail = (!diagnostic.is_empty()).then_some(diagnostic);
        self
    }

    /// Bounded, credential-redacted diagnostic retained for crash-loop status.
    pub fn diagnostic_tail(&self) -> Option<&str> {
        self.diagnostic_tail.as_deref()
    }
}

impl fmt::Display for EngineDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}; remediation: {}",
            self.reason, self.message, self.remediation
        )
    }
}

impl std::error::Error for EngineDriverError {}

fn sanitize_diagnostic_tail(diagnostic: &str) -> String {
    let mut lines = diagnostic.lines().rev();
    let mut retained = lines.by_ref().take(100).collect::<Vec<_>>();
    let trailing_marker_count = lines
        .flat_map(|line| line.split_whitespace().rev())
        .take_while(|token| is_sensitive_value_marker(token))
        .count();
    let redact_first_token = trailing_marker_count % 2 == 1;
    retained.reverse();
    let bounded = retained.join("\n").chars().take(8_192).collect::<String>();
    redact_sensitive_tokens_with_pending(&bounded, redact_first_token)
        .chars()
        .take(8_192)
        .collect()
}

fn bounded_operator_text(text: &str, max_chars: usize) -> String {
    let printable = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(max_chars)
        .collect::<String>();
    redact_sensitive_tokens(&printable)
        .chars()
        .take(max_chars)
        .collect()
}

fn redact_sensitive_tokens(text: &str) -> String {
    redact_sensitive_tokens_with_pending(text, false)
}

fn redact_sensitive_tokens_with_pending(text: &str, mut redact_next: bool) -> String {
    let mut redacted = Vec::new();
    for token in text.split_whitespace() {
        if redact_next {
            redacted.push("[REDACTED]".to_string());
            redact_next = false;
            continue;
        }

        if let Some(option) = attached_sensitive_option(token) {
            redacted.push(format!("{option}=[REDACTED]"));
            continue;
        }

        redacted.push(token.to_string());
        redact_next = is_sensitive_value_marker(token);
    }
    redacted.join(" ")
}

fn attached_sensitive_option(token: &str) -> Option<&'static str> {
    ["--api-key", "--token", "--hf-token"]
        .into_iter()
        .find(|option| {
            token
                .strip_prefix(option)
                .and_then(|suffix| suffix.strip_prefix('='))
                .is_some_and(|value| !value.is_empty())
        })
}

fn is_sensitive_value_marker(token: &str) -> bool {
    matches!(token, "--api-key" | "--token" | "--hf-token") || token_ends_with_bearer(token)
}

fn token_ends_with_bearer(token: &str) -> bool {
    let Some(prefix) = token.get(..token.len().saturating_sub("bearer".len())) else {
        return false;
    };
    let Some(suffix) = token.get(prefix.len()..) else {
        return false;
    };
    suffix.eq_ignore_ascii_case("bearer")
        && matches!(prefix.chars().next_back(), None | Some('"' | '\''))
}

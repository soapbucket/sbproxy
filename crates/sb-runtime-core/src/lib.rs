// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Runtime-neutral contracts shared by engine hosts and their consumers.

mod availability;
mod capability;
mod execution;
mod failure;
mod health;

pub use availability::{EngineAvailability, EngineDetection};
pub use capability::EngineCapabilities;
pub use execution::{EngineExecutionIdentity, EngineKind};
pub use failure::{EngineDriverError, EngineFailureReason};
pub use health::EngineHealth;

#[cfg(test)]
mod tests {
    use super::{
        EngineAvailability, EngineCapabilities, EngineDetection, EngineDriverError,
        EngineExecutionIdentity, EngineFailureReason, EngineHealth, EngineKind,
    };

    #[test]
    fn neutral_contract_describes_an_available_execution() {
        let detection = EngineDetection {
            kind: EngineKind::LlamaCpp,
            availability: EngineAvailability::Available,
            version: Some("b9905".to_string()),
            reason: "installed".to_string(),
            remediation: None,
        };
        let capabilities = EngineCapabilities {
            artifact_formats: vec!["gguf"],
            accelerators: vec!["cpu"],
            supports_container: false,
            supports_uv: false,
        };
        let execution = EngineExecutionIdentity {
            deployment: "local-qwen".to_string(),
            generation: 7,
            kind: EngineKind::LlamaCpp,
            port: 8081,
        };

        assert_eq!(detection.availability, EngineAvailability::Available);
        assert_eq!(capabilities.artifact_formats, vec!["gguf"]);
        assert_eq!(execution.kind, detection.kind);
        let health = serde_json::to_string(&EngineHealth::Ready);
        assert!(health.is_ok(), "health should serialize");
        assert_eq!(health.unwrap_or_default(), "\"ready\"");
        assert_eq!(
            EngineFailureReason::EngineReadinessTimeout.as_str(),
            "engine_readiness_timeout"
        );
    }

    #[test]
    fn wire_spellings_and_engine_identity_remain_stable() {
        let kind = serde_json::to_string(&EngineKind::SGLang);
        assert!(kind.is_ok(), "engine kind should serialize");
        assert_eq!(kind.unwrap_or_default(), "\"sglang\"");
        let availability = serde_json::to_string(&EngineAvailability::Acquirable);
        assert!(availability.is_ok(), "availability should serialize");
        assert_eq!(availability.unwrap_or_default(), "\"acquirable\"");
        let health = serde_json::to_string(&EngineHealth::Unhealthy);
        assert!(health.is_ok(), "health should serialize");
        assert_eq!(health.unwrap_or_default(), "\"unhealthy\"");
        assert_eq!(EngineKind::LlamaCpp.binary_name(), "llama-server");
        assert_eq!(
            EngineKind::MistralRs.request_model_id("deployment-a"),
            "default"
        );
    }

    #[test]
    fn execution_identity_validation_preserves_failure_order_and_messages() {
        let mut identity = EngineExecutionIdentity {
            deployment: " ".to_string(),
            generation: 0,
            kind: EngineKind::Vllm,
            port: 0,
        };

        let deployment = identity.validate();
        assert!(deployment.is_err(), "empty deployment should be invalid");
        let deployment = deployment.err().unwrap_or_else(|| {
            EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "missing deployment validation error",
                "fix the test",
                false,
            )
        });
        assert_eq!(deployment.reason(), EngineFailureReason::EngineInternal);
        assert_eq!(deployment.message(), "launch deployment must not be empty");

        identity.deployment = "deployment-a".to_string();
        let generation = identity.validate();
        assert!(generation.is_err(), "zero generation should be invalid");
        let generation = generation.err().unwrap_or_else(|| {
            EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "missing generation validation error",
                "fix the test",
                false,
            )
        });
        assert_eq!(generation.message(), "launch generation must be positive");

        identity.generation = 1;
        let port = identity.validate();
        assert!(port.is_err(), "zero port should be invalid");
        let port = port.err().unwrap_or_else(|| {
            EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "missing port validation error",
                "fix the test",
                false,
            )
        });
        assert_eq!(port.message(), "launch port must be positive");
        assert!(port.retryable());
    }

    #[test]
    fn operator_diagnostics_are_bounded_and_redacted() {
        let diagnostic = (0..120)
            .map(|index| format!("line-{index} bearer secret-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let error = EngineDriverError::new(
            EngineFailureReason::EngineSpawnFailed,
            format!("Bearer private-value {}", "x".repeat(2_100)),
            "\u{0007}",
            true,
        )
        .with_diagnostic_tail(diagnostic);

        assert!(error.message().chars().count() <= 2_048);
        assert!(!error.message().contains("private-value"));
        assert_eq!(
            error.remediation(),
            "inspect the model-host operation job and retry after correcting the cause"
        );
        let tail = error.diagnostic_tail();
        assert!(tail.is_some(), "diagnostic should be retained");
        let tail = tail.unwrap_or_default();
        assert!(!tail.contains("line-19"));
        assert!(tail.contains("line-20"));
        assert!(!tail.contains("secret-119"));
        assert!(tail.contains("bearer [REDACTED]"));
        assert!(tail.chars().count() <= 8_192);
    }

    #[test]
    fn operator_error_fields_redact_attached_option_credentials() {
        let error = EngineDriverError::new(
            EngineFailureReason::EngineSpawnFailed,
            "spawn failed --api-key=SYNTHETIC_CANARY",
            "retry without --token=SYNTHETIC_CANARY",
            false,
        )
        .with_diagnostic_tail("worker rejected --hf-token=SYNTHETIC_CANARY");

        assert_eq!(error.message(), "spawn failed --api-key=[REDACTED]");
        assert_eq!(error.remediation(), "retry without --token=[REDACTED]");
        assert_eq!(
            error.diagnostic_tail(),
            Some("worker rejected --hf-token=[REDACTED]")
        );
        assert!(!error.message().contains("SYNTHETIC_CANARY"));
        assert!(!error.remediation().contains("SYNTHETIC_CANARY"));
        assert!(!format!("{error:?}").contains("SYNTHETIC_CANARY"));
    }

    #[test]
    fn operator_error_redacts_quoted_authorization_bearer_value() {
        let error = EngineDriverError::new(
            EngineFailureReason::EngineSpawnFailed,
            r#"engine returned {"Authorization":"Bearer SYNTHETIC_CANARY"}"#,
            r#"remove {"authorization": "Bearer SYNTHETIC_CANARY"}"#,
            false,
        )
        .with_diagnostic_tail(r#"{"Authorization":"Bearer SYNTHETIC_CANARY"}"#);

        assert!(!error.message().contains("SYNTHETIC_CANARY"));
        assert!(!error.remediation().contains("SYNTHETIC_CANARY"));
        assert!(!error
            .diagnostic_tail()
            .unwrap_or_default()
            .contains("SYNTHETIC_CANARY"));
        assert!(!format!("{error:?}").contains("SYNTHETIC_CANARY"));
    }

    #[test]
    fn diagnostic_tail_redacts_token_split_across_retention_boundary() {
        let diagnostic = std::iter::once("Bearer".to_string())
            .chain(std::iter::once("SYNTHETIC_CANARY".to_string()))
            .chain((2..101).map(|index| format!("line-{index}")))
            .collect::<Vec<_>>()
            .join("\n");
        let error = EngineDriverError::new(
            EngineFailureReason::EngineEarlyExit,
            "engine exited",
            "inspect the diagnostic tail",
            true,
        )
        .with_diagnostic_tail(diagnostic);

        let tail = error.diagnostic_tail().unwrap_or_default();
        assert!(!tail.contains("SYNTHETIC_CANARY"));
        assert!(!format!("{error:?}").contains("SYNTHETIC_CANARY"));
        assert!(!tail.contains("Bearer"));
        assert!(tail.contains("[REDACTED]"));
        assert!(tail.contains("line-100"));
        assert!(tail.chars().count() <= 8_192);
    }

    #[test]
    fn diagnostic_tail_carries_redaction_across_discarded_blank_lines() {
        for blank_line in ["\n", " \t\n"] {
            let diagnostic = format!(
                "Bearer\n{blank_line}SYNTHETIC_CANARY\n{}",
                "safe\n".repeat(99)
            );
            let error = EngineDriverError::new(
                EngineFailureReason::EngineEarlyExit,
                "engine exited",
                "inspect the diagnostic tail",
                true,
            )
            .with_diagnostic_tail(diagnostic);

            let tail = error.diagnostic_tail().unwrap_or_default();
            assert!(!tail.contains("SYNTHETIC_CANARY"));
            assert!(!format!("{error:?}").contains("SYNTHETIC_CANARY"));
            assert!(tail.starts_with("[REDACTED]"));
            assert!(tail.chars().count() <= 8_192);
        }
    }

    #[test]
    fn consumed_marker_value_does_not_redact_retained_nonsecret_text() {
        let diagnostic = format!("--token\nBearer\n\nordinary\n{}", "safe\n".repeat(99));
        let error = EngineDriverError::new(
            EngineFailureReason::EngineEarlyExit,
            "engine exited",
            "inspect the diagnostic tail",
            true,
        )
        .with_diagnostic_tail(diagnostic);

        let tail = error.diagnostic_tail().unwrap_or_default();
        assert!(tail.starts_with("ordinary"));
        assert!(tail.chars().count() <= 8_192);
    }

    #[test]
    fn diagnostic_redaction_preserves_existing_whitespace_token_behavior() {
        let error = EngineDriverError::new(
            EngineFailureReason::EngineSpawnFailed,
            "  stable\nnonsecret\tmessage  ",
            "remove --api-key secret-value and retry",
            false,
        )
        .with_diagnostic_tail("alpha\nBearer\tsecret-value\nomega");

        assert_eq!(error.message(), "stable nonsecret message");
        assert_eq!(error.remediation(), "remove --api-key [REDACTED] and retry");
        assert_eq!(
            error.diagnostic_tail(),
            Some("alpha Bearer [REDACTED] omega")
        );
    }

    #[test]
    fn noncredential_bearer_suffix_remains_stable() {
        let error = EngineDriverError::new(
            EngineFailureReason::EngineSpawnFailed,
            "download public-bearer artifact",
            "keep stable value",
            false,
        );

        assert_eq!(error.message(), "download public-bearer artifact");
        assert_eq!(error.remediation(), "keep stable value");
    }
}

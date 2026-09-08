// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{EngineDriverError, EngineFailureReason};

/// Which inference engine serves a model.
///
/// The closed enum is an execution identity, not an arbitrary command. A host
/// owns the argument template and executable resolution for each variant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// vLLM, served over its OpenAI-compatible HTTP surface.
    #[default]
    Vllm,
    /// SGLang, served over its OpenAI-compatible HTTP surface.
    #[serde(rename = "sglang")]
    SGLang,
    /// llama.cpp `llama-server`, the GGUF and edge path.
    LlamaCpp,
    /// mistral.rs through its unified `mistralrs` binary.
    #[serde(rename = "mistralrs")]
    MistralRs,
}

impl EngineKind {
    /// Binary name associated with this engine identity.
    pub fn binary_name(self) -> &'static str {
        match self {
            Self::Vllm => "vllm",
            Self::SGLang => "sglang",
            Self::LlamaCpp => "llama-server",
            Self::MistralRs => "mistralrs",
        }
    }

    /// Model identifier accepted by this engine for a managed deployment.
    pub fn request_model_id(self, deployment: &str) -> &str {
        match self {
            Self::Vllm | Self::SGLang | Self::LlamaCpp => deployment,
            Self::MistralRs => "default",
        }
    }
}

/// Stable data-only identity shared by launch and running-engine paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EngineExecutionIdentity {
    /// Canonical deployment ID.
    pub deployment: String,
    /// Monotonic deployment generation.
    pub generation: u64,
    /// Managed engine kind.
    pub kind: EngineKind,
    /// Loopback serving port allocated by the host.
    pub port: u16,
}

impl EngineExecutionIdentity {
    /// Validate the host-independent execution identity fields.
    pub fn validate(&self) -> Result<(), EngineDriverError> {
        if self.deployment.trim().is_empty() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "launch deployment must not be empty",
                "reconcile a valid canonical deployment before launching",
                false,
            ));
        }
        if self.generation == 0 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "launch generation must be positive",
                "reconcile a numbered deployment generation before launching",
                false,
            ));
        }
        if self.port == 0 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "launch port must be positive",
                "allocate an unused loopback port before launching",
                true,
            ));
        }
        Ok(())
    }
}

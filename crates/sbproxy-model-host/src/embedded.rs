// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! In-process embedded inference engine (WOR-1658), behind the
//! `embedded` cargo feature.
//!
//! Loads a model with mistral.rs and serves an OpenAI-compatible
//! `/v1/chat/completions` (plus `/health`) on a loopback port, so the
//! model-host runtime routes to it exactly like a supervised subprocess
//! engine: [`crate::launch::ProcessEngineLauncher`] dispatches an
//! [`crate::config::EngineKind::Embedded`] spec here instead of
//! spawning. Any mistral.rs-supported architecture works (Gemma, Qwen,
//! Llama, ...); the served model id comes from the serve entry.
//!
//! The whole module compiles only under `--features embedded`, which
//! pulls the (large) mistral.rs + axum dependency trees; the default
//! build and lockfile path stay lean.

use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use mistralrs::{IsqBits, Model, ModelBuilder, TextMessageRole, TextMessages};
use serde_json::{json, Value};
use tokio::sync::oneshot;

/// A running in-process engine: the loaded model served over a loopback
/// OpenAI endpoint, plus the handle to stop it.
#[derive(Debug)]
pub struct EmbeddedServer {
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl EmbeddedServer {
    /// Load `repo` with mistral.rs (in-situ 4-bit quantized so it fits
    /// broadly) and start the loopback OpenAI server on `port`. Awaits
    /// the model load, so a returned `Ok` means the engine is genuinely
    /// ready to serve (the runtime's readiness probe then confirms
    /// `/health`). `repo` is a Hugging Face model id such as
    /// `google/gemma-2-2b-it`; gated repos need `HF_TOKEN` in the env.
    pub async fn start(repo: &str, port: u16) -> Result<Self, String> {
        let model = ModelBuilder::new(repo)
            .with_auto_isq(IsqBits::Four)
            .with_logging()
            .build()
            .await
            .map_err(|e| format!("load embedded model '{repo}': {e}"))?;

        let app = Router::new()
            .route("/health", get(health))
            .route("/v1/chat/completions", post(chat_completions))
            .with_state(Arc::new(model));

        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind embedded server {addr}: {e}"))?;

        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });
        Ok(Self {
            shutdown: Some(tx),
            task,
        })
    }

    /// Stop the server and drop the model (freeing VRAM/RAM).
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

async fn health() -> &'static str {
    "ok"
}

/// Minimal OpenAI `/v1/chat/completions` over the in-process model:
/// translate the request's messages to mistral.rs, run the model, and
/// return the completion in OpenAI shape (content + token usage).
async fn chat_completions(State(model): State<Arc<Model>>, Json(req): Json<Value>) -> Json<Value> {
    let mut messages = TextMessages::new();
    if let Some(arr) = req.get("messages").and_then(|m| m.as_array()) {
        for m in arr {
            let role = match m.get("role").and_then(Value::as_str) {
                Some("system") => TextMessageRole::System,
                Some("assistant") => TextMessageRole::Assistant,
                _ => TextMessageRole::User,
            };
            let content = m.get("content").and_then(Value::as_str).unwrap_or_default();
            messages = messages.add_message(role, content);
        }
    }
    match model.send_chat_request(messages).await {
        Ok(resp) => {
            let text = resp
                .choices
                .first()
                .and_then(|c| c.message.content.clone())
                .unwrap_or_default();
            Json(json!({
                "object": "chat.completion",
                "model": req.get("model").cloned().unwrap_or(Value::Null),
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }],
                "usage": {
                    "prompt_tokens": resp.usage.prompt_tokens,
                    "completion_tokens": resp.usage.completion_tokens,
                    "total_tokens": resp.usage.total_tokens,
                },
            }))
        }
        Err(e) => Json(json!({"error": {"message": format!("embedded inference failed: {e}")}})),
    }
}

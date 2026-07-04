// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Request-path glue for locally-served models (WOR-1680).
//!
//! A provider that carries a `serve:` block hosts its models on this
//! box: the gateway spawns an engine and the request must route to that
//! engine's loopback port, not to a `base_url`. The engine lifecycle
//! lives in [`sbproxy_model_host::ModelHostRuntime`], which is generic
//! over its launcher; [`LocalModelHost`] is the object-safe view of it
//! so the dispatcher can hold `&dyn LocalModelHost` (and tests can
//! inject a fake engine with no GPU).
//!
//! [`resolve_served_base_url`] is the seam the dispatcher calls after it
//! has selected a provider: it maps the requested model to a served
//! entry, brings that engine to ready, and returns the loopback base
//! URL to overwrite the provider's `base_url` with. Providers without a
//! `serve:` block are untouched (the caller keeps `effective_base_url`).

use async_trait::async_trait;

use sbproxy_model_host::{ModelHostRuntime, ProcessEngineLauncher, RuntimeError};

use crate::provider::ProviderConfig;

/// Object-safe view of the local model host for request-path dispatch.
/// Implemented by [`ModelHostRuntime`] for any launcher; a test double
/// implements it directly to stand in for a real engine.
#[async_trait]
pub trait LocalModelHost: Send + Sync {
    /// Bring the named served model to ready, returning its loopback
    /// port. Idempotent: an already-ready model returns fast.
    async fn ensure_ready(&self, name: &str) -> Result<u16, RuntimeError>;

    /// The loopback base URL (`http://127.0.0.1:<port>/v1`) for a ready
    /// model, or `None` when it is not resident/ready.
    async fn resolved_base_url(&self, name: &str) -> Option<String>;
}

// Implemented for the concrete production runtime (the process
// launcher). A generic `impl<L: EngineLauncher>` would require the
// launcher's `async fn`s to yield `Send` futures, which the trait does
// not promise; `ProcessEngineLauncher` does, and it is the only
// launcher the gateway ever runs.
#[async_trait]
impl LocalModelHost for ModelHostRuntime<ProcessEngineLauncher> {
    async fn ensure_ready(&self, name: &str) -> Result<u16, RuntimeError> {
        ModelHostRuntime::ensure_ready(self, name).await
    }

    async fn resolved_base_url(&self, name: &str) -> Option<String> {
        ModelHostRuntime::resolved_base_url(self, name).await
    }
}

/// Choose which served model a request targets, given the served entry
/// names, the request's model (if any), and the provider default.
///
/// Precedence: an explicit request model that names a served entry, then
/// the provider `default_model` if it names one, then the sole served
/// entry when there is exactly one. Ambiguous (several entries, no
/// match) returns `None` so the caller can report a clear error rather
/// than route to an arbitrary engine.
fn pick_served_name(
    names: &[String],
    requested_model: Option<&str>,
    provider: &ProviderConfig,
) -> Option<String> {
    if let Some(m) = requested_model {
        if names.iter().any(|n| n == m) {
            return Some(m.to_string());
        }
    }
    if let Some(dm) = &provider.default_model {
        let dm = dm.as_str();
        if names.iter().any(|n| n == dm) {
            return Some(dm.to_string());
        }
    }
    if names.len() == 1 {
        return Some(names[0].clone());
    }
    None
}

/// Resolve a served provider's upstream to its live loopback base URL,
/// spawning and loading the engine as needed.
///
/// Returns `Ok(None)` when the provider has no `serve:` block, so the
/// caller keeps the provider's normal [`ProviderConfig::effective_base_url`].
/// On a served provider it brings the chosen engine to ready and returns
/// `Ok(Some(url))`.
///
/// # Errors
///
/// - the served entries are misconfigured (duplicate/nameless);
/// - the request names no served model and there is no unambiguous
///   default;
/// - the engine could not be brought to ready (fit, residency, launch).
pub async fn resolve_served_base_url(
    provider: &ProviderConfig,
    requested_model: Option<&str>,
    host: &dyn LocalModelHost,
) -> Result<Option<String>, String> {
    let Some(serve) = &provider.serve else {
        return Ok(None);
    };
    let names = serve.model_names()?;
    let name = pick_served_name(&names, requested_model, provider).ok_or_else(|| {
        format!(
            "provider {:?} serves {names:?}: request model {requested_model:?} matches none and there is no unique default; set the request model or a default_model",
            provider.name.as_str()
        )
    })?;
    host.ensure_ready(&name)
        .await
        .map_err(|e| format!("provider {:?} serve {name:?}: {e}", provider.name.as_str()))?;
    Ok(host.resolved_base_url(&name).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};

    /// A fake host: ensure_ready records the name and returns a fixed
    /// port; resolved_base_url returns the loopback URL for it.
    #[derive(Default)]
    struct FakeHost {
        port: AtomicU16,
        last: std::sync::Mutex<Option<String>>,
    }

    #[async_trait]
    impl LocalModelHost for FakeHost {
        async fn ensure_ready(&self, name: &str) -> Result<u16, RuntimeError> {
            *self.last.lock().unwrap() = Some(name.to_string());
            self.port.store(41999, Ordering::SeqCst);
            Ok(41999)
        }
        async fn resolved_base_url(&self, _name: &str) -> Option<String> {
            let p = self.port.load(Ordering::SeqCst);
            (p != 0).then(|| format!("http://127.0.0.1:{p}/v1"))
        }
    }

    fn provider_with_serve(serve_yaml: &str, default_model: Option<&str>) -> ProviderConfig {
        let serve: sbproxy_model_host::ModelHostConfig =
            serde_yaml::from_str(serve_yaml).expect("serve config");
        let mut p = ProviderConfig {
            name: "local".into(),
            provider_type: None,
            api_key: None,
            base_url: None,
            models: Vec::new(),
            default_model: default_model.map(Into::into),
            model_map: std::collections::HashMap::new(),
            weight: 1,
            priority: None,
            enabled: true,
            max_retries: None,
            timeout_ms: None,
            organization: None,
            api_version: None,
            host_override: None,
            disable_forwarded_host_header: false,
            allow_private_base_url: false,
            no_prompt_training: false,
            serve: None,
        };
        p.serve = Some(serve);
        p
    }

    #[tokio::test]
    async fn no_serve_block_returns_none() {
        let mut p = provider_with_serve("models:\n  - model: qwen3-14b\n", None);
        p.serve = None;
        let host = FakeHost::default();
        assert_eq!(
            resolve_served_base_url(&p, Some("gpt-4o"), &host)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn sole_served_model_resolves_without_a_request_model() {
        let p = provider_with_serve("models:\n  - model: qwen3-14b\n", None);
        let host = FakeHost::default();
        let url = resolve_served_base_url(&p, None, &host).await.unwrap();
        assert_eq!(url.as_deref(), Some("http://127.0.0.1:41999/v1"));
        assert_eq!(host.last.lock().unwrap().as_deref(), Some("qwen3-14b"));
    }

    #[tokio::test]
    async fn request_model_selects_among_several_served() {
        let p = provider_with_serve(
            "models:\n  - model: qwen3-14b\n  - model: hf:Org/Coder:Q4\n    name: coder\n",
            None,
        );
        let host = FakeHost::default();
        let url = resolve_served_base_url(&p, Some("coder"), &host)
            .await
            .unwrap();
        assert_eq!(url.as_deref(), Some("http://127.0.0.1:41999/v1"));
        assert_eq!(host.last.lock().unwrap().as_deref(), Some("coder"));
    }

    #[tokio::test]
    async fn ambiguous_several_served_without_match_errors() {
        let p = provider_with_serve(
            "models:\n  - model: qwen3-14b\n  - model: hf:Org/Coder:Q4\n    name: coder\n",
            None,
        );
        let host = FakeHost::default();
        let err = resolve_served_base_url(&p, Some("unknown"), &host)
            .await
            .unwrap_err();
        assert!(err.contains("matches none"), "clear error: {err}");
    }

    #[tokio::test]
    async fn default_model_picks_when_request_absent() {
        let p = provider_with_serve(
            "models:\n  - model: qwen3-14b\n  - model: hf:Org/Coder:Q4\n    name: coder\n",
            Some("coder"),
        );
        let host = FakeHost::default();
        let url = resolve_served_base_url(&p, None, &host).await.unwrap();
        assert_eq!(url.as_deref(), Some("http://127.0.0.1:41999/v1"));
        assert_eq!(host.last.lock().unwrap().as_deref(), Some("coder"));
    }

    /// A host whose `ensure_ready` actually binds a minimal OpenAI-shaped
    /// engine on a loopback port, so a real HTTP round trip can be made
    /// against the resolved URL, no GPU or real engine involved.
    struct FakeEngineHost {
        port: AtomicU16,
    }

    impl FakeEngineHost {
        async fn spawn() -> Self {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio::net::TcpListener;
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((mut s, _)) = listener.accept().await else {
                        return;
                    };
                    // Read the request (ignore contents) then answer a
                    // canned OpenAI chat completion.
                    let mut buf = [0u8; 2048];
                    let _ = s.read(&mut buf).await;
                    let body = r#"{"id":"cmpl-fake","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                }
            });
            Self {
                port: AtomicU16::new(port),
            }
        }
    }

    #[async_trait]
    impl LocalModelHost for FakeEngineHost {
        async fn ensure_ready(&self, _name: &str) -> Result<u16, RuntimeError> {
            Ok(self.port.load(Ordering::SeqCst))
        }
        async fn resolved_base_url(&self, _name: &str) -> Option<String> {
            Some(format!(
                "http://127.0.0.1:{}/v1",
                self.port.load(Ordering::SeqCst)
            ))
        }
    }

    #[tokio::test]
    async fn serve_only_provider_completes_a_chat_round_trip_on_cpu() {
        // WOR-1680 acceptance: a provider whose body is just serve:
        // (no address anywhere) resolves to a live engine and a chat
        // completion round-trips, on a CPU with a fake engine.
        let host = FakeEngineHost::spawn().await;
        let provider = provider_with_serve("models:\n  - model: qwen3-14b\n", None);
        assert!(provider.base_url.is_none(), "no address in config");

        let base = resolve_served_base_url(&provider, Some("qwen3-14b"), &host)
            .await
            .unwrap()
            .expect("served provider resolves to a URL");

        // Real HTTP POST to the resolved engine URL.
        let resp = reqwest::Client::new()
            .post(format!("{base}/chat/completions"))
            .json(&serde_json::json!({
                "model": "qwen3-14b",
                "messages": [{"role": "user", "content": "hi"}]
            }))
            .send()
            .await
            .expect("request reaches the resolved engine");
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            v["choices"][0]["message"]["content"], "hi",
            "engine returned a completion"
        );
    }
}

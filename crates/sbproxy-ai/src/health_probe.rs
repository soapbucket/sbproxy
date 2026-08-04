//! Active health probes for the AI provider pool (WOR-2224).
//!
//! [`Router`] intersects three independent signals before a provider
//! can take a request: the circuit breaker, the outlier detector, and
//! the active-probe health flag. The first two learn only from real
//! traffic, so they cannot know a provider is down until a request has
//! already been spent discovering it. This module drives the third by
//! asking each provider directly on a fixed interval, which is what
//! lets a cold provider be skipped before the first request of a burst
//! picks it.
//!
//! The probe tasks are the only production writer of that flag. The
//! config block that turns them on (`resilience.health_check`) parsed
//! for months while nothing read it, so every provider sat at the
//! `unknown` default and the axis contributed nothing while appearing
//! to; [`spawn_provider_health_probes`] is the missing caller.

use std::sync::{Arc, Weak};
use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};

use crate::handler::{AiHandlerConfig, AiHealthCheckConfig};
use crate::provider::ProviderConfig;
use crate::routing::Router;

/// Spawn one probe task per enabled provider when the handler config
/// carries a `resilience.health_check` block, and return how many were
/// started.
///
/// Spawns on the ambient Tokio runtime and returns 0 when there is
/// none. The proxy reaches this through the pipeline's publication
/// boundary, which owns a runtime and calls
/// [`spawn_provider_health_probes_on`] directly.
///
/// The count is returned rather than discarded so a test can assert
/// that a config asking for probes actually gets them. The defect this
/// module exists to fix was a config block nothing ever read, and a
/// spawn count is the cheapest assertion that fails if the wiring is
/// ever cut again.
pub fn spawn_provider_health_probes(config: &AiHandlerConfig) -> usize {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return 0;
    };
    spawn_provider_health_probes_on(config, &handle)
}

/// Spawn the same per-provider probes on a caller-owned runtime.
///
/// A pipeline generation is compiled before Pingora creates its service
/// runtimes, and a candidate generation may be rejected before it ever
/// serves traffic, so the publication boundary starts probes on a
/// process-lifetime runtime rather than whichever short-lived runtime
/// happened to compile the pipeline. Reaching for the ambient runtime
/// here would panic on that path instead.
pub fn spawn_provider_health_probes_on(
    config: &AiHandlerConfig,
    handle: &tokio::runtime::Handle,
) -> usize {
    let Some(cfg) = config
        .resilience
        .as_ref()
        .and_then(|resilience| resilience.health_check.as_ref())
    else {
        return 0;
    };

    let router = config.router();
    let mut spawned = 0;

    for (provider_idx, provider) in config.providers.iter().enumerate() {
        // A disabled provider is filtered out before the health axis is
        // ever consulted, so probing it would be outbound traffic that
        // cannot change a routing decision.
        if !provider.enabled {
            continue;
        }
        let Some(probe_url) = probe_url_for(provider, &cfg.path) else {
            continue;
        };
        let Some(auth) = auth_header_for(provider) else {
            tracing::warn!(
                provider = %provider.name,
                "ai health probe disabled for provider: credential is not a valid header"
            );
            continue;
        };

        // A probe holds a weak handle so it retires itself. A config
        // reload builds a new pipeline and drops the old one, taking
        // the last strong reference to this router with it; a strong
        // handle here would instead keep every superseded config's
        // providers under a permanent probe load, one extra task per
        // provider per reload, for the life of the process.
        let router = Arc::downgrade(&router);
        let cfg = cfg.clone();
        let provider_name = provider.name.to_string();
        handle.spawn(async move {
            run_probe_loop(router, provider_idx, provider_name, probe_url, auth, cfg).await;
        });
        spawned += 1;
    }

    spawned
}

/// Consecutive-result counters backing one provider's probe.
#[derive(Debug, Default)]
struct ProbeCounters {
    consecutive_ok: u32,
    consecutive_fail: u32,
}

impl ProbeCounters {
    /// Fold one probe result in and return the verdict to publish, or
    /// `None` when the evidence so far is not enough to move the flag.
    ///
    /// Thresholds count *consecutive* results, so a single stray
    /// timeout inside an otherwise healthy series cannot eject a
    /// provider, and a single lucky response cannot revive one.
    fn observe(&mut self, ok: bool, cfg: &AiHealthCheckConfig) -> Option<bool> {
        if ok {
            self.consecutive_fail = 0;
            self.consecutive_ok = self.consecutive_ok.saturating_add(1);
            (self.consecutive_ok >= cfg.healthy_threshold).then_some(true)
        } else {
            self.consecutive_ok = 0;
            self.consecutive_fail = self.consecutive_fail.saturating_add(1);
            (self.consecutive_fail >= cfg.unhealthy_threshold).then_some(false)
        }
    }
}

/// Whether one probe response counts as the provider being up.
///
/// Anything that answers with a status line has proved it is reachable
/// and serving, so only a 5xx counts against a provider. That is a
/// deliberate departure from the load balancer's probe, which requires
/// a 2xx: an operator chooses that probe path on an upstream they
/// control, while these base URLs and the default `/models` path come
/// from the vendor catalog and differ per vendor. Under a 2xx rule a
/// wrong key (401), a vendor with no `/models` route (404), or a busy
/// account (429) would eject every provider at once, and
/// `Router::select_with_policy` deliberately does not revive a fully
/// ejected set. A probe must not be able to cause the outage it exists
/// to prevent.
fn response_is_healthy(status: reqwest::StatusCode) -> bool {
    !status.is_server_error()
}

/// Build the probe URL for one provider, or `None` when the configured
/// path is unusable.
fn probe_url_for(provider: &ProviderConfig, path: &str) -> Option<String> {
    if !path.starts_with('/') {
        tracing::warn!(
            provider = %provider.name,
            path = %path,
            "ai health probe disabled for provider: probe path must start with /"
        );
        return None;
    }
    let base = provider.effective_base_url();
    // `build_url` is the same joiner the request path uses, so a probe
    // and a real call agree about a base URL that already ends in the
    // version segment the path repeats.
    Some(crate::client::build_url(base.trim_end_matches('/'), path))
}

/// Format one provider's credential as a request header.
///
/// Providers authenticate with `Authorization`, `x-api-key`, or
/// `api-key` depending on the vendor, and the probe has to send the
/// same one the request path would: an unauthenticated `/models` is a
/// 401 at most vendors, which is a statement about the probe rather
/// than about the provider.
fn auth_header_for(provider: &ProviderConfig) -> Option<(HeaderName, HeaderValue)> {
    let (name, value) = provider.auth_header();
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    let mut value = HeaderValue::from_str(&value).ok()?;
    value.set_sensitive(true);
    Some((name, value))
}

/// One provider's probe: the parts that do not change between ticks,
/// plus the consecutive-result counters that do.
struct ProviderProbe {
    client: reqwest::Client,
    probe_url: String,
    auth: (HeaderName, HeaderValue),
    cfg: AiHealthCheckConfig,
    provider_idx: usize,
    provider_name: String,
    counters: ProbeCounters,
}

impl ProviderProbe {
    /// Run one probe and publish a verdict if a threshold was crossed.
    ///
    /// Returns the verdict published, or `None` when the provider's
    /// current flag was left alone.
    async fn tick(&mut self, router: &Router) -> Option<bool> {
        let ok = match self
            .client
            .get(&self.probe_url)
            .header(self.auth.0.clone(), self.auth.1.clone())
            .send()
            .await
        {
            Ok(response) => response_is_healthy(response.status()),
            // No status line at all: DNS, connect, TLS, or the timeout.
            Err(_) => false,
        };

        // The verdict goes to the health axis and nowhere else. The
        // load balancer's probe also feeds its outlier detector, but
        // the two recover on different terms: the detector clears an
        // ejection when its own timer expires, this probe clears when
        // `healthy_threshold` probes pass in a row. Writing one signal
        // into both would leave a provider that is answering again
        // ejected until an unrelated timer agreed. Keeping the axes
        // separate lets the eligibility check intersect them, so each
        // recovers on the terms that match the evidence it collected.
        let verdict = self.counters.observe(ok, &self.cfg)?;
        router.set_provider_health(self.provider_idx, verdict);
        tracing::debug!(
            provider = %self.provider_name,
            healthy = verdict,
            "ai health probe verdict"
        );
        Some(verdict)
    }
}

/// Probe one provider on `interval_secs` until its router goes away.
async fn run_probe_loop(
    router: Weak<Router>,
    provider_idx: usize,
    provider_name: String,
    probe_url: String,
    auth: (HeaderName, HeaderValue),
    cfg: AiHealthCheckConfig,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms))
        .user_agent(format!("sbproxy-healthcheck/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(
                provider = %provider_name,
                error = %error,
                "ai health probe disabled for provider: client build failed"
            );
            return;
        }
    };

    // `tokio::time::interval` panics on a zero period, and this one
    // comes straight from operator YAML.
    let period = Duration::from_secs(cfg.interval_secs.max(1));
    let mut ticker = tokio::time::interval(period);
    // A probe that fell behind should resume on the next boundary
    // rather than fire once per missed tick to catch up.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut probe = ProviderProbe {
        client,
        probe_url,
        auth,
        cfg,
        provider_idx,
        provider_name,
        counters: ProbeCounters::default(),
    };

    loop {
        ticker.tick().await;
        let Some(router) = router.upgrade() else {
            return;
        };
        // The verdict is already published to the router by `tick`; the
        // return value exists for the tests that assert on it.
        let _ = probe.tick(&router).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingStrategy;

    fn cfg(unhealthy_threshold: u32, healthy_threshold: u32) -> AiHealthCheckConfig {
        AiHealthCheckConfig {
            path: "/models".to_string(),
            interval_secs: 30,
            timeout_ms: 500,
            unhealthy_threshold,
            healthy_threshold,
        }
    }

    fn provider_json(name: &str, base_url: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "provider_type": "openai",
            "api_key": "test-key",
            "base_url": base_url,
            "allow_private_base_url": true,
        })
    }

    /// Serve `count` requests, each answered with `status`, then stop.
    async fn serve_status(status: u16, count: usize) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe stub");
        let address = listener.local_addr().expect("probe stub address");
        tokio::spawn(async move {
            for _ in 0..count {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer).await;
                let response = format!(
                    "HTTP/1.1 {status} PROBE\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}"
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
        });
        format!("http://{address}")
    }

    #[test]
    fn unhealthy_is_published_only_after_consecutive_failures() {
        let cfg = cfg(3, 2);
        let mut counters = ProbeCounters::default();
        assert_eq!(counters.observe(false, &cfg), None);
        assert_eq!(counters.observe(false, &cfg), None);
        assert_eq!(counters.observe(false, &cfg), Some(false));
    }

    #[test]
    fn healthy_is_published_only_after_consecutive_successes() {
        let cfg = cfg(3, 2);
        let mut counters = ProbeCounters::default();
        assert_eq!(counters.observe(true, &cfg), None);
        assert_eq!(counters.observe(true, &cfg), Some(true));
    }

    #[test]
    fn a_single_stray_result_resets_the_opposing_run() {
        let cfg = cfg(3, 2);
        let mut counters = ProbeCounters::default();
        counters.observe(false, &cfg);
        counters.observe(false, &cfg);
        // One success here must not be enough to publish, and it must
        // put the failure run back to zero rather than leaving the
        // provider one bad probe from ejection.
        assert_eq!(counters.observe(true, &cfg), None);
        assert_eq!(counters.observe(false, &cfg), None);
        assert_eq!(counters.observe(false, &cfg), None);
        assert_eq!(counters.observe(false, &cfg), Some(false));
    }

    #[test]
    fn only_a_server_error_counts_against_a_provider() {
        for status in [200, 201, 400, 401, 403, 404, 429] {
            assert!(
                response_is_healthy(reqwest::StatusCode::from_u16(status).expect("status")),
                "{status} says the provider answered, so it must not eject it"
            );
        }
        for status in [500, 502, 503, 504] {
            assert!(
                !response_is_healthy(reqwest::StatusCode::from_u16(status).expect("status")),
                "{status} is the provider failing and must count against it"
            );
        }
    }

    #[test]
    fn a_probe_path_without_a_leading_slash_is_refused() {
        let provider: ProviderConfig =
            serde_json::from_value(provider_json("openai", "http://127.0.0.1:1/v1"))
                .expect("provider");
        assert_eq!(probe_url_for(&provider, "models"), None);
    }

    #[test]
    fn the_probe_url_joins_the_base_without_repeating_the_version_segment() {
        let provider: ProviderConfig =
            serde_json::from_value(provider_json("openai", "https://api.example.com/v1"))
                .expect("provider");
        assert_eq!(
            probe_url_for(&provider, "/models").as_deref(),
            Some("https://api.example.com/v1/models")
        );
    }

    #[test]
    fn the_probe_sends_the_providers_own_credential_header() {
        let provider: ProviderConfig =
            serde_json::from_value(provider_json("openai", "https://api.example.com/v1"))
                .expect("provider");
        let (name, value) = auth_header_for(&provider).expect("auth header");
        assert_eq!(name.as_str(), "authorization");
        assert!(
            value.is_sensitive(),
            "the probe's credential must be redaction-marked like the request path's"
        );
    }

    /// The regression this module exists for. A failing provider must
    /// actually leave the routing set, end to end: probe -> health flag
    /// -> `select`. With no probe writing the flag, every assertion
    /// after the first one here fails.
    #[tokio::test]
    async fn a_failing_provider_is_probed_out_of_the_routing_set() {
        let cfg = cfg(2, 2);
        let base_url = serve_status(503, 2).await;
        let providers: Vec<ProviderConfig> = vec![
            serde_json::from_value(provider_json("failing", &base_url)).expect("provider"),
            serde_json::from_value(provider_json("healthy", "https://api.example.com/v1"))
                .expect("provider"),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len());
        let mut probe = ProviderProbe {
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(500))
                .build()
                .expect("probe client"),
            probe_url: probe_url_for(&providers[0], "/models").expect("probe url"),
            auth: auth_header_for(&providers[0]).expect("auth header"),
            cfg,
            provider_idx: 0,
            provider_name: "failing".to_string(),
            counters: ProbeCounters::default(),
        };

        // Both providers are selectable before any probe has run.
        let mut before = std::collections::HashSet::new();
        for _ in 0..4 {
            before.insert(router.select(&providers).expect("a provider"));
        }
        assert_eq!(before, [0, 1].into_iter().collect());

        assert_eq!(
            probe.tick(&router).await,
            None,
            "one 503 is not yet enough to eject"
        );
        assert_eq!(
            probe.tick(&router).await,
            Some(false),
            "the threshold was reached"
        );

        // The routing decision now avoids the failing provider.
        for _ in 0..4 {
            assert_eq!(
                router.select(&providers),
                Some(1),
                "a probed-unhealthy provider must not be selected"
            );
        }
    }

    /// A config that asks for probes must get them. This is the shape
    /// of the original defect: `resilience.health_check` deserialized
    /// cleanly while nothing spawned a single task.
    #[tokio::test]
    async fn a_health_check_block_spawns_one_probe_per_enabled_provider() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                provider_json("first", "http://127.0.0.1:1/v1"),
                provider_json("second", "http://127.0.0.1:2/v1"),
                {
                    "name": "third",
                    "provider_type": "openai",
                    "api_key": "test-key",
                    "base_url": "http://127.0.0.1:3/v1",
                    "allow_private_base_url": true,
                    "enabled": false,
                },
            ],
            "resilience": {
                "health_check": {
                    "path": "/models",
                    "interval_secs": 3600,
                },
            },
        }))
        .expect("config compiles");

        assert_eq!(
            spawn_provider_health_probes(&config),
            2,
            "one probe per enabled provider, and none for the disabled one"
        );
    }

    #[tokio::test]
    async fn no_health_check_block_spawns_nothing() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [provider_json("first", "http://127.0.0.1:1/v1")],
        }))
        .expect("config compiles");

        assert_eq!(spawn_provider_health_probes(&config), 0);
    }
}

//! HTTP ledger client.
//!
//! Sync (blocking) by design: the [`Ledger`] trait is sync because
//! the policy fast-path lives inside Pingora's request filter, which
//! does not own a tokio runtime handle. We use `reqwest::blocking`
//! the same way the WAF rule-feed loader does at config-compile.
//! For high-rps deployments the circuit breaker bounds the cost of
//! a slow ledger to one round-trip + breaker-open period.
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rand::Rng;
use sbproxy_platform::CircuitBreaker;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use super::{Ledger, LedgerError, RedeemResult};

type HmacSha256 = Hmac<Sha256>;

/// Configuration for `HttpLedger`.
#[derive(Debug, Clone)]
pub struct HttpLedgerConfig {
    /// Base URL, e.g. `https://ledger.internal`. The client appends
    /// `/v1/ledger/redeem` (and other verb paths in later waves).
    /// Plain HTTP is rejected at construction time per the ADR.
    pub endpoint: String,
    /// HMAC key id (selects which key on the ledger side validates
    /// the signature).
    pub key_id: String,
    /// HMAC key bytes. Loaded from `SBPROXY_LEDGER_HMAC_KEY_FILE`
    /// in the binary; tests pass raw bytes.
    pub key: Vec<u8>,
    /// Workspace tenant key. `default` in OSS, the customer
    /// workspace id in enterprise.
    pub workspace_id: String,
    /// Agent identifier from the agent-class taxonomy. The
    /// Wave 1 caller forwards `unknown` until G1.4 lands; widening
    /// the call site is a follow-up.
    pub agent_id: String,
    /// Convenience copy of the taxonomy `vendor` carried so the
    /// ledger does not need to load the taxonomy.
    pub agent_vendor: String,
    /// Per-attempt deadline; the client aborts the request after
    /// this many milliseconds and counts it as a transient failure.
    pub per_attempt_timeout: Duration,
    /// Total deadline across all retries.
    pub total_timeout: Duration,
    /// Maximum retry attempts. Hard-capped at 5 by the ADR.
    pub max_attempts: u32,
    /// Consecutive failures that open the circuit breaker.
    pub breaker_failure_threshold: u32,
    /// Successes in `HalfOpen` to close the breaker again.
    pub breaker_success_threshold: u32,
    /// Duration the breaker stays open before allowing a probe.
    pub breaker_open_duration: Duration,
}

impl HttpLedgerConfig {
    /// Defaults aligned with the ADR (5 attempts, 5 s per attempt,
    /// 30 s total, breaker opens after 10 failures, 5 s open).
    pub fn with_defaults(
        endpoint: impl Into<String>,
        key_id: impl Into<String>,
        key: Vec<u8>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            key_id: key_id.into(),
            key,
            workspace_id: "default".to_string(),
            agent_id: "unknown".to_string(),
            agent_vendor: "unknown".to_string(),
            per_attempt_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            max_attempts: 5,
            breaker_failure_threshold: 10,
            breaker_success_threshold: 1,
            breaker_open_duration: Duration::from_secs(5),
        }
    }
}

/// HTTP ledger client.
pub struct HttpLedger {
    config: HttpLedgerConfig,
    client: reqwest::blocking::Client,
    breaker: Arc<CircuitBreaker>,
    /// Optional recency probe stamped on every successful redeem.
    /// When wired into `sbproxy_observe::default_registry`, this
    /// is what flips `/readyz` from 503 to 200 once the ledger
    /// answers a real request. Left as `None` for tests and for
    /// configs that do not expose `/readyz`.
    recency: Option<sbproxy_observe::Recency>,
}

impl std::fmt::Debug for HttpLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpLedger")
            .field("endpoint", &self.config.endpoint)
            .field("key_id", &self.config.key_id)
            .field("workspace_id", &self.config.workspace_id)
            .field("agent_id", &self.config.agent_id)
            .finish()
    }
}

impl HttpLedger {
    /// Build a new client. Returns `Err` if `endpoint` is not HTTPS.
    pub fn new(config: HttpLedgerConfig) -> anyhow::Result<Self> {
        // The ADR mandates HTTPS for the ledger endpoint. A plain
        // HTTP target is almost always a misconfiguration, so we
        // refuse to construct the client rather than fail later.
        if !config.endpoint.starts_with("https://") {
            anyhow::bail!(
                "HttpLedger endpoint must be https://; got '{}'",
                config.endpoint
            );
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(config.per_attempt_timeout)
            .build()?;
        let breaker = Arc::new(CircuitBreaker::new(
            config.breaker_failure_threshold,
            config.breaker_success_threshold,
            config.breaker_open_duration,
        ));
        Ok(Self {
            config,
            client,
            breaker,
            recency: None,
        })
    }

    /// Inject a custom HTTP client (used by tests to point at a
    /// stub server with a relaxed TLS config).
    pub fn with_client(mut self, client: reqwest::blocking::Client) -> Self {
        self.client = client;
        self
    }

    /// Inject a custom circuit breaker, e.g. one shared across
    /// multiple verbs in a future wave.
    pub fn with_breaker(mut self, breaker: Arc<CircuitBreaker>) -> Self {
        self.breaker = breaker;
        self
    }

    /// Wire a `Recency` clone so every successful redeem stamps
    /// the readiness probe. The same `Recency` should be passed
    /// to `sbproxy_observe::default_registry(...)` at startup so
    /// `/readyz` returns 200 once the ledger answers a real
    /// request and 503 once it has been silent for longer than
    /// the configured staleness window.
    pub fn with_recency(mut self, recency: sbproxy_observe::Recency) -> Self {
        self.recency = Some(recency);
        self
    }

    /// Expose the breaker state for `/readyz` and Grafana dashboards.
    pub fn breaker(&self) -> &CircuitBreaker {
        &self.breaker
    }
}

impl Ledger for HttpLedger {
    fn redeem(
        &self,
        token: &str,
        host: &str,
        path: &str,
        expected_amount_micros: u64,
        expected_currency: &str,
    ) -> Result<RedeemResult, LedgerError> {
        // --- Breaker gate ---
        //
        // When open we short-circuit with a synthetic transient
        // error; the policy at the request path then emits 503.
        if !self.breaker.allow_request() {
            return Err(
                LedgerError::transient("ledger.unavailable", "circuit breaker open")
                    .with_retry_after(self.config.breaker_open_duration.as_secs().max(1) as u32),
            );
        }

        // --- Request envelope ---
        let request_id = Ulid::new().to_string();
        let idempotency_key = Ulid::new().to_string();
        let nonce = random_nonce_hex();
        let timestamp = rfc3339_millis_now();
        let envelope = RedeemEnvelope {
            v: 1,
            request_id: request_id.clone(),
            timestamp: timestamp.clone(),
            nonce: nonce.clone(),
            agent_id: self.config.agent_id.clone(),
            agent_vendor: self.config.agent_vendor.clone(),
            workspace_id: self.config.workspace_id.clone(),
            payload: RedeemPayload {
                token: token.to_string(),
                host: host.to_string(),
                path: path.to_string(),
                amount_micros: expected_amount_micros,
                currency: expected_currency.to_string(),
                content_shape: None,
            },
        };
        let body_bytes = serde_json::to_vec(&envelope).map_err(|e| {
            LedgerError::hard("ledger.bad_request", format!("envelope encode: {e}"))
        })?;
        let body_hash_hex = sha256_hex(&body_bytes);

        let path_only = "/v1/ledger/redeem";
        let signing_string = canonical_signing_string(
            envelope.v,
            &request_id,
            &timestamp,
            &nonce,
            &self.config.workspace_id,
            "POST",
            path_only,
            &body_hash_hex,
        );
        let signature_hex = hmac_sha256_hex(&self.config.key, signing_string.as_bytes())
            .map_err(|e| LedgerError::hard("ledger.bad_request", format!("hmac init: {e}")))?;
        let signature_header = format!("v1={signature_hex}");

        let url = format!(
            "{}{}",
            self.config.endpoint.trim_end_matches('/'),
            path_only
        );

        // --- Retry loop ---
        //
        // Schedule per ADR: 0 ms, 250 ms, 500 ms, 1 s, 2 s base
        // delay, each with `[0, base)` jitter added. Same Idempotency-Key
        // across retries so the ledger short-circuits on replay.
        let max_attempts = self.config.max_attempts.clamp(1, 5);
        let total_deadline = Instant::now() + self.config.total_timeout;
        let mut last_err: Option<LedgerError> = None;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                let base_ms = match attempt {
                    1 => 250u64,
                    2 => 500,
                    3 => 1000,
                    _ => 2000,
                };
                let jitter_ms = rand::thread_rng().gen_range(0..base_ms.max(1));
                let delay = Duration::from_millis(base_ms + jitter_ms);
                if Instant::now() + delay >= total_deadline {
                    break;
                }
                std::thread::sleep(delay);
            }
            if Instant::now() >= total_deadline {
                break;
            }
            match self.send_attempt(
                &url,
                &body_bytes,
                &idempotency_key,
                &request_id,
                &signature_header,
            ) {
                Ok(result) => {
                    self.breaker.record_success();
                    if let Some(r) = &self.recency {
                        r.mark_success();
                    }
                    return Ok(result);
                }
                Err(err) => {
                    if err.retryable {
                        self.breaker.record_failure();
                        last_err = Some(err);
                        continue;
                    }
                    // Hard failure: do not retry, do not flap the
                    // breaker. The policy will translate to 402.
                    return Err(err);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            LedgerError::transient("ledger.unavailable", "max retries exhausted")
        }))
    }
}

impl HttpLedger {
    fn send_attempt(
        &self,
        url: &str,
        body: &[u8],
        idempotency_key: &str,
        request_id: &str,
        signature_header: &str,
    ) -> Result<RedeemResult, LedgerError> {
        let response = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("idempotency-key", idempotency_key)
            .header("x-sb-ledger-signature", signature_header)
            .header("x-sb-ledger-key-id", &self.config.key_id)
            .header("x-sb-request-id", request_id)
            .body(body.to_vec())
            .send();

        let response = match response {
            Ok(r) => r,
            Err(e) => {
                // Network errors (DNS, TCP RST, TLS, read timeout)
                // are always retryable.
                return Err(LedgerError::transient(
                    "ledger.unavailable",
                    format!("network: {e}"),
                ));
            }
        };

        let status = response.status();
        let retry_after_header = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok());
        let body_text = response.text().unwrap_or_default();

        if status.is_success() {
            let envelope: ResponseEnvelope = serde_json::from_str(&body_text).map_err(|e| {
                LedgerError::transient("ledger.internal", format!("decode response: {e}"))
            })?;
            if let Some(result) = envelope.result {
                let redeemed = result.redeemed.unwrap_or(false);
                if !redeemed {
                    return Err(LedgerError::hard(
                        "ledger.token_already_spent",
                        "ledger reported redeemed=false",
                    ));
                }
                return Ok(RedeemResult {
                    token_id: result
                        .redemption_id
                        .unwrap_or_else(|| request_id.to_string()),
                    amount_micros: result.amount_micros.unwrap_or(0),
                    currency: result.currency.unwrap_or_default(),
                    txhash: result.txhash,
                });
            }
            if let Some(err) = envelope.error {
                return Err(map_envelope_error(err, retry_after_header));
            }
            return Err(LedgerError::transient(
                "ledger.internal",
                "response missing result and error",
            ));
        }

        // Non-2xx: try to decode the error envelope, otherwise
        // synthesize one from the HTTP status.
        let envelope: Option<ResponseEnvelope> = serde_json::from_str(&body_text).ok();
        if let Some(err) = envelope.and_then(|e| e.error) {
            return Err(map_envelope_error(err, retry_after_header));
        }
        let code = status.as_u16();
        match code {
            400 => Err(LedgerError::hard(
                "ledger.bad_request",
                format!("HTTP {code}"),
            )),
            401 => Err(LedgerError::hard(
                "ledger.signature_invalid",
                format!("HTTP {code}"),
            )),
            409 => Err(LedgerError::hard(
                "ledger.token_already_spent",
                format!("HTTP {code}"),
            )),
            429 => {
                let mut e = LedgerError::transient("ledger.rate_limited", format!("HTTP {code}"));
                if let Some(s) = retry_after_header {
                    e = e.with_retry_after(s);
                }
                Err(e)
            }
            502..=504 => {
                let mut e = LedgerError::transient("ledger.unavailable", format!("HTTP {code}"));
                if let Some(s) = retry_after_header {
                    e = e.with_retry_after(s);
                }
                Err(e)
            }
            _ if (500..600).contains(&code) => Err(LedgerError::transient(
                "ledger.internal",
                format!("HTTP {code}"),
            )),
            _ => Err(LedgerError::hard(
                "ledger.bad_request",
                format!("HTTP {code}"),
            )),
        }
    }
}

fn map_envelope_error(err: ErrorPart, retry_after_header: Option<u32>) -> LedgerError {
    let mut out = LedgerError {
        code: err.code,
        message: err.message,
        retryable: err.retryable,
        retry_after_seconds: err.retry_after_seconds,
    };
    if out.retry_after_seconds.is_none() {
        out.retry_after_seconds = retry_after_header;
    }
    out
}

// --- Wire types ---

#[derive(Debug, Serialize)]
struct RedeemEnvelope {
    v: u32,
    request_id: String,
    timestamp: String,
    nonce: String,
    agent_id: String,
    agent_vendor: String,
    workspace_id: String,
    payload: RedeemPayload,
}

#[derive(Debug, Serialize)]
struct RedeemPayload {
    token: String,
    host: String,
    path: String,
    amount_micros: u64,
    currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_shape: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResponseEnvelope {
    #[serde(default)]
    result: Option<ResultPart>,
    #[serde(default)]
    error: Option<ErrorPart>,
}

#[derive(Debug, Deserialize)]
struct ResultPart {
    #[serde(default)]
    redeemed: Option<bool>,
    #[serde(default)]
    redemption_id: Option<String>,
    #[serde(default)]
    amount_micros: Option<u64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    txhash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorPart {
    code: String,
    message: String,
    #[serde(default)]
    retryable: bool,
    #[serde(default)]
    retry_after_seconds: Option<u32>,
}

// --- Helpers ---

#[allow(clippy::too_many_arguments)] // canonical signing string is 8 fields by spec.
fn canonical_signing_string(
    v: u32,
    request_id: &str,
    timestamp: &str,
    nonce: &str,
    workspace_id: &str,
    method: &str,
    path: &str,
    body_hash_hex: &str,
) -> String {
    // Eight lines, \n separated, no trailing newline (per ADR).
    format!(
            "{v}\n{request_id}\n{timestamp}\n{nonce}\n{workspace_id}\n{method}\n{path}\n{body_hash_hex}"
        )
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| e.to_string())?;
    mac.update(data);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn random_nonce_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn rfc3339_millis_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    // Manual format avoids pulling chrono::Utc::now() which is
    // already in the dep tree but not used elsewhere on this hot
    // path. RFC 3339 / ISO 8601 form.
    let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, millis * 1_000_000)
        .unwrap_or_default();
    datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

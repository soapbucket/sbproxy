//! ACME client (RFC 8555) for automatic certificate provisioning.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rcgen::{CertificateParams, DistinguishedName, KeyPair as RcgenKeyPair};
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as RingKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::cert_store::CertStore;
use crate::challenges::Http01ChallengeStore;
use sbproxy_platform::KVStore;

// --- ACME directory URLs ---

/// Let's Encrypt production ACME directory.
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Let's Encrypt staging ACME directory (for testing without rate limits).
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

// --- ACME JSON types ---

/// ACME directory object returned by the directory URL.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    /// URL used to fetch a fresh anti-replay nonce.
    pub new_nonce: String,
    /// URL used to register or look up an ACME account.
    pub new_account: String,
    /// URL used to create a new ACME order.
    pub new_order: String,
}

/// ACME order object.
#[derive(Debug, Deserialize)]
pub struct Order {
    /// Current order status (e.g. "pending", "ready", "valid", "invalid").
    pub status: String,
    /// Authorization URLs that must be satisfied before finalization.
    pub authorizations: Vec<String>,
    /// URL to POST the CSR to once authorizations are valid.
    pub finalize: String,
    /// Issued certificate URL once the order reaches the "valid" state.
    pub certificate: Option<String>,
}

/// ACME authorization object.
#[derive(Debug, Deserialize)]
pub struct Authorization {
    /// Current authorization status (e.g. "pending", "valid", "invalid").
    pub status: String,
    /// Identifier the authorization applies to.
    pub identifier: Identifier,
    /// Challenges offered by the server to satisfy this authorization.
    pub challenges: Vec<Challenge>,
}

/// ACME identifier (domain name).
#[derive(Debug, Deserialize)]
pub struct Identifier {
    /// Identifier type (typically "dns").
    #[serde(rename = "type")]
    pub id_type: String,
    /// Identifier value (e.g. the DNS hostname).
    pub value: String,
}

/// ACME challenge (HTTP-01, TLS-ALPN-01, DNS-01, etc.).
#[derive(Debug, Deserialize)]
pub struct Challenge {
    /// Challenge type identifier (e.g. "http-01", "tls-alpn-01", "dns-01").
    #[serde(rename = "type")]
    pub challenge_type: String,
    /// Challenge URL the client posts to in order to signal readiness.
    pub url: String,
    /// Challenge token used to compute the key authorization.
    pub token: String,
    /// Current challenge status (e.g. "pending", "valid", "invalid").
    pub status: String,
}

/// Pick a challenge from an ACME authorization, honouring the caller's
/// preferred-type list. Returns the first authorization challenge
/// whose `challenge_type` matches an entry in `preferred`, in
/// preference order. Falls through to the first `http-01` challenge
/// when no preference matches so empty / unknown configs still work.
///
/// Pulled out as a free function so tests can exercise selection
/// without standing up a full ACME client.
fn pick_challenge<'a>(challenges: &'a [Challenge], preferred: &[String]) -> Option<&'a Challenge> {
    for want in preferred {
        if let Some(c) = challenges
            .iter()
            .find(|c| c.challenge_type.eq_ignore_ascii_case(want))
        {
            return Some(c);
        }
    }
    // Fall back to http-01 if the operator's preference list is
    // empty or contains only types the authorization does not
    // advertise. This keeps a freshly-installed proxy running
    // without explicit challenge configuration.
    challenges.iter().find(|c| c.challenge_type == "http-01")
}

// --- AcmeClient ---

/// ACME client that handles account key management and the ACME API protocol.
pub struct AcmeClient {
    http: reqwest::Client,
    directory_url: String,
    directory: Option<Directory>,
    email: String,
    /// Preferred challenge types in priority order (e.g.,
    /// `["http-01", "tls-alpn-01"]`). The first entry that the ACME
    /// authorization advertises wins. `http-01` is the only type the
    /// proxy can fully drive today; selecting any other type surfaces
    /// a warning and falls back to `http-01` when available.
    challenge_types: Vec<String>,
    /// Cached account URL (kid) after registration.
    kid: Option<String>,
}

impl AcmeClient {
    /// Create a new ACME client targeting the given directory URL.
    ///
    /// `challenge_types` lists preferred challenge types in priority order
    /// (e.g., `["http-01", "tls-alpn-01"]`).
    ///
    /// When the directory URL contains "localhost", the HTTP client will
    /// automatically accept invalid TLS certificates (for Pebble testing).
    pub fn new(directory_url: &str, email: &str, challenge_types: Vec<String>) -> Self {
        let accept_invalid =
            directory_url.contains("localhost") || directory_url.contains("127.0.0.1");
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_invalid)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            http,
            directory_url: directory_url.to_owned(),
            directory: None,
            email: email.to_owned(),
            challenge_types,
            kid: None,
        }
    }

    /// Fetch (and cache) the ACME directory from the server.
    pub async fn fetch_directory(&mut self) -> Result<&Directory> {
        if self.directory.is_none() {
            let dir: Directory = self
                .http
                .get(&self.directory_url)
                .send()
                .await
                .context("GET directory")?
                .error_for_status()
                .context("directory response error")?
                .json()
                .await
                .context("parse directory JSON")?;
            self.directory = Some(dir);
        }
        Ok(self.directory.as_ref().unwrap())
    }

    /// Request a fresh nonce from the ACME server via HEAD on `newNonce`.
    pub async fn new_nonce(&self) -> Result<String> {
        let dir = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow!("directory not fetched; call fetch_directory first"))?;

        let resp = self
            .http
            .head(&dir.new_nonce)
            .send()
            .await
            .context("HEAD newNonce")?;

        let nonce = resp
            .headers()
            .get("replay-nonce")
            .ok_or_else(|| anyhow!("missing Replay-Nonce header"))?
            .to_str()
            .context("Replay-Nonce not ASCII")?
            .to_owned();

        Ok(nonce)
    }

    /// Load the ACME account key from the store, or generate a fresh one and persist it.
    ///
    /// Returns an `EcdsaKeyPair` (P-256 / SHA-256).
    pub fn load_or_create_account_key<S: KVStore>(store: &CertStore<S>) -> Result<EcdsaKeyPair> {
        if let Some(pem_bytes) = store.get_account_key().context("read account key")? {
            // Parse existing key
            let pkcs8 = pem_to_pkcs8(&pem_bytes).context("decode stored account key PEM")?;
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &pkcs8,
                &SystemRandom::new(),
            )
            .map_err(|e| anyhow!("parse stored PKCS8 key: {e}"))?;
            return Ok(key_pair);
        }

        // Generate a fresh P-256 key
        let rng = SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| anyhow!("generate ECDSA key: {e}"))?;
        let pkcs8_bytes = pkcs8_doc.as_ref();

        // Persist as PEM
        let pem = pkcs8_to_pem(pkcs8_bytes);
        store
            .put_account_key(pem.as_bytes())
            .context("store account key")?;

        // Parse and return
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes, &rng)
            .map_err(|e| anyhow!("create EcdsaKeyPair: {e}"))?;
        Ok(key_pair)
    }

    /// Compute the ACME key authorization: `"{token}.{jwk_thumbprint}"`.
    pub fn key_authorization(token: &str, key_pair: &EcdsaKeyPair) -> String {
        let thumbprint = jwk_thumbprint(key_pair);
        format!("{}.{}", token, thumbprint)
    }

    // --- JWS signing ---

    /// Sign a payload as a JWS (RFC 7515) using the account key.
    ///
    /// Returns the serialized JWS JSON that can be POST'd to ACME endpoints.
    /// When `kid` is `None` the JWS header embeds the full JWK (used for
    /// `newAccount` where the server doesn't know us yet). When `kid` is
    /// `Some(url)` it embeds the account URL instead.
    fn sign_jws(
        key_pair: &EcdsaKeyPair,
        url: &str,
        nonce: &str,
        payload: &serde_json::Value,
        kid: Option<&str>,
    ) -> Result<String> {
        // --- Build the protected header ---
        let header = if let Some(kid_url) = kid {
            serde_json::json!({
                "alg": "ES256",
                "nonce": nonce,
                "url": url,
                "kid": kid_url
            })
        } else {
            // New-account: embed the JWK (public key).
            let jwk = build_jwk(key_pair);
            serde_json::json!({
                "alg": "ES256",
                "nonce": nonce,
                "url": url,
                "jwk": jwk
            })
        };

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());

        // --- Encode payload ---
        // An empty string payload signals POST-as-GET (RFC 8555 §6.3).
        let payload_b64 = if payload.is_string() && payload.as_str() == Some("") {
            String::new()
        } else {
            URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes())
        };

        // --- Sign ---
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let rng = SystemRandom::new();
        let sig = key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|e| anyhow!("ECDSA sign failed: {e}"))?;

        // ring returns ASN.1 DER-encoded signature; ACME (ES256) needs raw r||s (64 bytes).
        let sig_b64 = URL_SAFE_NO_PAD.encode(der_to_raw_ecdsa_p256(sig.as_ref())?);

        // --- Assemble ---
        let jws = serde_json::json!({
            "protected": header_b64,
            "payload": payload_b64,
            "signature": sig_b64
        });

        Ok(jws.to_string())
    }

    /// POST a JWS-signed request to an ACME endpoint and return the raw response.
    ///
    /// Per RFC 8555 §6.5, the server may reject a request with
    /// `urn:ietf:params:acme:error:badNonce` and the client MUST retry
    /// with a fresh nonce. We retry once; persistent failure indicates
    /// a real problem (clock skew, wrong key, etc.) and bubbles up.
    async fn post_jws(
        &self,
        key_pair: &EcdsaKeyPair,
        url: &str,
        payload: &serde_json::Value,
        kid: Option<&str>,
    ) -> Result<reqwest::Response> {
        let resp = self.post_jws_once(key_pair, url, payload, kid).await?;

        if resp.status() != reqwest::StatusCode::BAD_REQUEST {
            return Ok(resp);
        }

        // 400 might be badNonce; peek at the body to decide. We can only
        // consume the body once, so if it is NOT badNonce we wrap the
        // body bytes in a synthetic anyhow error so the original message
        // still reaches the caller's error path.
        let body_bytes = resp
            .bytes()
            .await
            .context("read 400 response body for badNonce check")?;
        let is_bad_nonce = serde_json::from_slice::<serde_json::Value>(&body_bytes)
            .ok()
            .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned))
            == Some("urn:ietf:params:acme:error:badNonce".to_string());

        if !is_bad_nonce {
            return Err(anyhow!(
                "POST {url} returned 400: {}",
                String::from_utf8_lossy(&body_bytes)
            ));
        }

        debug!(
            url,
            "ACME server rejected JWS with badNonce; retrying once with fresh nonce"
        );
        self.post_jws_once(key_pair, url, payload, kid).await
    }

    /// One-shot JWS POST. Always grabs a fresh nonce, signs, sends,
    /// returns whatever the server replied with. Wrapped by `post_jws`
    /// for badNonce retry behavior.
    async fn post_jws_once(
        &self,
        key_pair: &EcdsaKeyPair,
        url: &str,
        payload: &serde_json::Value,
        kid: Option<&str>,
    ) -> Result<reqwest::Response> {
        let nonce = self.new_nonce().await.context("get nonce for JWS post")?;
        let body = Self::sign_jws(key_pair, url, &nonce, payload, kid).context("sign JWS")?;

        let resp = self
            .http
            .post(url)
            .header("Content-Type", "application/jose+json")
            .body(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;

        Ok(resp)
    }

    // --- Account registration ---

    /// Register a new ACME account (or retrieve an existing one) for the given key pair.
    ///
    /// Returns the account URL (kid) from the `Location` response header.
    pub async fn register_account(&mut self, key_pair: &EcdsaKeyPair) -> Result<String> {
        // Ensure directory is loaded.
        self.fetch_directory().await?;

        let new_account_url = self.directory.as_ref().unwrap().new_account.clone();

        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", self.email)]
        });

        let resp = self
            .post_jws(key_pair, &new_account_url, &payload, None)
            .await
            .context("POST newAccount")?;

        // 200 = existing account found, 201 = new account created - both are OK.
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("newAccount returned {status}: {body}"));
        }

        let kid = resp
            .headers()
            .get("location")
            .ok_or_else(|| anyhow!("newAccount response missing Location header"))?
            .to_str()
            .context("Location header not ASCII")?
            .to_owned();

        info!("ACME account registered/retrieved: {}", kid);
        self.kid = Some(kid.clone());
        Ok(kid)
    }

    // --- Order creation ---

    /// Create an ACME order for `hostname`.
    ///
    /// Returns `(order_url, order)`.
    pub async fn create_order(
        &self,
        key_pair: &EcdsaKeyPair,
        kid: &str,
        hostname: &str,
    ) -> Result<(String, Order)> {
        let new_order_url = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow!("directory not fetched"))?
            .new_order
            .clone();

        let payload = serde_json::json!({
            "identifiers": [{"type": "dns", "value": hostname}]
        });

        let resp = self
            .post_jws(key_pair, &new_order_url, &payload, Some(kid))
            .await
            .context("POST newOrder")?;

        let status = resp.status();
        let order_url = resp
            .headers()
            .get("location")
            .ok_or_else(|| anyhow!("newOrder response missing Location header"))?
            .to_str()
            .context("Location header not ASCII")?
            .to_owned();

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("newOrder returned {status}: {body}"));
        }

        let order: Order = resp.json().await.context("parse order JSON")?;
        debug!(
            hostname,
            order_url, "order created with status: {}", order.status
        );
        Ok((order_url, order))
    }

    // --- Authorization fetch ---

    /// Fetch an ACME authorization object from `auth_url`.
    pub async fn fetch_authorization(
        &self,
        key_pair: &EcdsaKeyPair,
        kid: &str,
        auth_url: &str,
    ) -> Result<Authorization> {
        // POST-as-GET: empty string payload.
        let resp = self
            .post_jws(
                key_pair,
                auth_url,
                &serde_json::Value::String(String::new()),
                Some(kid),
            )
            .await
            .context("POST-as-GET authorization")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "fetch authorization {auth_url} returned {status}: {body}"
            ));
        }

        let auth: Authorization = resp.json().await.context("parse authorization JSON")?;
        Ok(auth)
    }

    // --- Challenge response ---

    /// Signal the ACME server that a challenge is ready to be validated.
    pub async fn respond_to_challenge(
        &self,
        key_pair: &EcdsaKeyPair,
        kid: &str,
        challenge_url: &str,
    ) -> Result<()> {
        // RFC 8555 §7.5.1: POST an empty JSON object `{}` to indicate readiness.
        let resp = self
            .post_jws(key_pair, challenge_url, &serde_json::json!({}), Some(kid))
            .await
            .context("POST challenge")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "challenge response {challenge_url} returned {status}: {body}"
            ));
        }

        debug!(challenge_url, "challenge responded to");
        Ok(())
    }

    // --- Order finalization ---

    /// Finalize an ACME order by sending a CSR.
    ///
    /// Generates a fresh P-256 key and CSR for `hostname`, then POSTs the
    /// base64url-encoded DER CSR to `finalize_url`.
    ///
    /// Returns `(csr_key_pem, order_url_to_poll)`.
    pub async fn finalize_order(
        &self,
        key_pair: &EcdsaKeyPair,
        kid: &str,
        finalize_url: &str,
        hostname: &str,
    ) -> Result<(String, Vec<u8>)> {
        // Generate a fresh key pair for the certificate (separate from the account key).
        let cert_key = RcgenKeyPair::generate().context("generate cert key pair")?;
        let key_pem = cert_key.serialize_pem().into_bytes();

        // Build a CSR.
        let mut params =
            CertificateParams::new(vec![hostname.to_owned()]).context("create CSR params")?;
        params.distinguished_name = DistinguishedName::new();

        let csr = params
            .serialize_request(&cert_key)
            .context("serialize CSR")?;
        let csr_der = csr.der();
        let csr_b64 = URL_SAFE_NO_PAD.encode(csr_der.as_ref());

        let payload = serde_json::json!({"csr": csr_b64});

        let resp = self
            .post_jws(key_pair, finalize_url, &payload, Some(kid))
            .await
            .context("POST finalize")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("finalize {finalize_url} returned {status}: {body}"));
        }

        // The order URL for polling is in the Location header (may be missing if already valid).
        let order_url = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(finalize_url)
            .to_owned();

        debug!(hostname, "order finalized, polling {}", order_url);
        Ok((order_url, key_pem))
    }

    // --- Certificate download ---

    /// Download the issued certificate chain from `cert_url`.
    ///
    /// Uses POST-as-GET (RFC 8555 §7.4.2). Returns PEM bytes.
    pub async fn download_cert(
        &self,
        key_pair: &EcdsaKeyPair,
        kid: &str,
        cert_url: &str,
    ) -> Result<Vec<u8>> {
        // POST-as-GET: empty string payload.
        let resp = self
            .post_jws(
                key_pair,
                cert_url,
                &serde_json::Value::String(String::new()),
                Some(kid),
            )
            .await
            .context("POST-as-GET certificate")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "download cert {cert_url} returned {status}: {body}"
            ));
        }

        let bytes = resp.bytes().await.context("read cert response body")?;
        Ok(bytes.to_vec())
    }

    // --- Order polling ---

    /// Poll `order_url` until the order status is "valid" or "invalid".
    ///
    /// Uses exponential backoff starting at 1s, doubling up to 30s.
    /// Returns the final `Order` on success, or an error if the order becomes
    /// invalid or the timeout is exceeded.
    pub async fn poll_order(
        &self,
        key_pair: &EcdsaKeyPair,
        kid: &str,
        order_url: &str,
        timeout: Duration,
    ) -> Result<Order> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut delay = Duration::from_secs(1);

        loop {
            let resp = self
                .post_jws(
                    key_pair,
                    order_url,
                    &serde_json::Value::String(String::new()),
                    Some(kid),
                )
                .await
                .context("poll order")?;

            let status_code = resp.status();
            if !status_code.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow!(
                    "poll order {order_url} returned {status_code}: {body}"
                ));
            }

            let order: Order = resp.json().await.context("parse polled order JSON")?;
            debug!(order_url, "poll order status: {}", order.status);

            match order.status.as_str() {
                "valid" => return Ok(order),
                "invalid" => return Err(anyhow!("ACME order became invalid: {order_url}")),
                _ => {
                    // Still pending/processing - back off and retry.
                    if tokio::time::Instant::now() >= deadline {
                        return Err(anyhow!(
                            "timed out polling order {order_url} after {:?}",
                            timeout
                        ));
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    // --- Full issuance orchestration ---

    /// Orchestrate the full ACME certificate issuance flow for `hostname`.
    ///
    /// Steps:
    /// 1. Register account (or reuse cached kid).
    /// 2. Create order for hostname.
    /// 3. Fetch authorization, find HTTP-01 challenge.
    /// 4. Compute key authorization, store in challenge_store.
    /// 5. Respond to challenge.
    /// 6. Poll order until "ready".
    /// 7. Finalize with fresh CSR.
    /// 8. Poll order until "valid".
    /// 9. Download certificate chain.
    /// 10. Clean up challenge from store.
    ///
    /// Returns `(cert_pem, key_pem)`.
    pub async fn issue_cert(
        &mut self,
        key_pair: &EcdsaKeyPair,
        hostname: &str,
        challenge_store: &Http01ChallengeStore,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        info!(hostname, "starting ACME certificate issuance");

        // --- Step 1: register or reuse account ---
        let kid = if let Some(ref cached_kid) = self.kid {
            cached_kid.clone()
        } else {
            self.register_account(key_pair)
                .await
                .context("register ACME account")?
        };

        // --- Step 2: create order ---
        let (order_url, order) = self
            .create_order(key_pair, &kid, hostname)
            .await
            .context("create ACME order")?;

        if order.authorizations.is_empty() {
            return Err(anyhow!(
                "ACME order returned no authorizations for {hostname}"
            ));
        }

        // --- Step 3: fetch authorization and find HTTP-01 challenge ---
        let auth_url = &order.authorizations[0];
        let auth = self
            .fetch_authorization(key_pair, &kid, auth_url)
            .await
            .context("fetch authorization")?;

        let challenge =
            pick_challenge(&auth.challenges, &self.challenge_types).ok_or_else(|| {
                anyhow!(
                    "no usable challenge found in authorization for {hostname}: \
                     advertised={:?} preferred={:?}",
                    auth.challenges
                        .iter()
                        .map(|c| c.challenge_type.as_str())
                        .collect::<Vec<_>>(),
                    self.challenge_types,
                )
            })?;
        if challenge.challenge_type != "http-01" {
            // Selected a configured non-HTTP-01 type but the proxy
            // can only physically respond to HTTP-01 today (the
            // `Http01ChallengeStore` answers `/.well-known/acme-challenge/...`
            // requests during the validation window). Falling through
            // here is a clear bug surface; surfacing as an error is
            // safer than silently failing the order.
            return Err(anyhow!(
                "challenge type '{}' selected but only http-01 is currently driven by the proxy; \
                 add 'http-01' to your `challenge_types` preference list",
                challenge.challenge_type
            ));
        }

        let token = challenge.token.clone();
        let challenge_url = challenge.url.clone();

        // --- Step 4: register key authorization in challenge store ---
        let key_auth = Self::key_authorization(&token, key_pair);
        challenge_store.set(&token, &key_auth);
        debug!(hostname, token, "http-01 challenge token registered");

        // --- Step 5: respond to challenge ---
        self.respond_to_challenge(key_pair, &kid, &challenge_url)
            .await
            .context("respond to http-01 challenge")?;

        // --- Step 6: poll until order is "ready" (challenges validated) ---
        let order = self
            .poll_order(key_pair, &kid, &order_url, Duration::from_secs(120))
            .await
            .context("poll order to ready/valid")?;

        // --- Step 7: finalize with CSR (if not already valid) ---
        let (final_poll_url, key_pem) = if order.status == "valid" {
            // Already valid (e.g., cached by ACME server). Use order_url as-is.
            warn!(
                hostname,
                "order already valid before finalization (unexpected)"
            );
            (order_url.clone(), {
                // We still need a cert key; generate one and store separately.
                // Normally this path is not taken.
                let k = RcgenKeyPair::generate().context("generate fallback cert key")?;
                k.serialize_pem().into_bytes()
            })
        } else {
            let finalize_url = order.finalize.clone();
            self.finalize_order(key_pair, &kid, &finalize_url, hostname)
                .await
                .context("finalize order")?
        };

        // --- Step 8: poll until order is "valid" ---
        let final_order = self
            .poll_order(key_pair, &kid, &final_poll_url, Duration::from_secs(120))
            .await
            .context("poll order to valid after finalization")?;

        // --- Step 9: download certificate ---
        let cert_url = final_order
            .certificate
            .ok_or_else(|| anyhow!("order is valid but missing certificate URL"))?;

        let cert_pem = self
            .download_cert(key_pair, &kid, &cert_url)
            .await
            .context("download certificate")?;

        // --- Step 10: clean up challenge ---
        challenge_store.remove(&token);
        debug!(hostname, "http-01 challenge token removed");

        info!(hostname, "ACME certificate issued successfully");
        Ok((cert_pem, key_pem))
    }
}

// --- PEM helpers ---

/// Strip PEM armor and decode the base64 body to raw DER/PKCS8 bytes.
fn pem_to_pkcs8(pem: &[u8]) -> Result<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem).context("PEM is not UTF-8")?;
    let body: String = pem_str
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .context("base64 decode PEM body")
}

/// Wrap raw DER/PKCS8 bytes in PEM armor (`PRIVATE KEY`).
/// Lines are wrapped at 64 characters per RFC 7468.
fn pkcs8_to_pem(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

// --- JWK helpers (RFC 7638) ---

/// Build an RFC 7517 JWK object for an ECDSA P-256 public key.
fn build_jwk(key_pair: &EcdsaKeyPair) -> serde_json::Value {
    let pub_key_bytes = key_pair.public_key().as_ref();
    // Uncompressed point: 0x04 || x[32] || y[32]
    let x = &pub_key_bytes[1..33];
    let y = &pub_key_bytes[33..65];
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y)
    })
}

/// Compute the RFC 7638 JWK thumbprint for an ECDSA P-256 key pair.
///
/// The thumbprint is `BASE64URL(SHA-256(canonical_jwk_json))` where the
/// canonical JSON is `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`.
fn jwk_thumbprint(key_pair: &EcdsaKeyPair) -> String {
    // The public key in uncompressed form: 0x04 || x[32] || y[32]
    // This is always true for P-256 keys generated by ring, but we
    // debug_assert to catch misuse during development without panicking in production.
    let pub_key_bytes = key_pair.public_key().as_ref();
    debug_assert_eq!(
        pub_key_bytes.len(),
        65,
        "unexpected P-256 public key length"
    );
    debug_assert_eq!(
        pub_key_bytes[0], 0x04,
        "public key not in uncompressed form"
    );

    let x = &pub_key_bytes[1..33];
    let y = &pub_key_bytes[33..65];

    let x_b64 = URL_SAFE_NO_PAD.encode(x);
    let y_b64 = URL_SAFE_NO_PAD.encode(y);

    // RFC 7638 canonical JSON: keys in lexicographic order
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64, y_b64
    );

    let hash = digest(&SHA256, canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

// --- ECDSA signature conversion ---

/// Convert an ASN.1 DER-encoded ECDSA-P256 signature to the raw r||s form
/// (64 bytes) required by ES256 (RFC 7518 §3.4).
///
/// DER structure: SEQUENCE { INTEGER r, INTEGER s }
/// Each integer may have a leading 0x00 padding byte if the high bit is set.
fn der_to_raw_ecdsa_p256(der: &[u8]) -> Result<Vec<u8>> {
    // Minimal DER parse: SEQUENCE { INTEGER r, INTEGER s }
    // Format: 0x30 <seq_len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>
    if der.len() < 8 || der[0] != 0x30 {
        return Err(anyhow!("invalid DER signature: missing SEQUENCE tag"));
    }

    let mut pos = 2usize; // skip tag + length

    // Parse r
    if der[pos] != 0x02 {
        return Err(anyhow!("invalid DER signature: expected INTEGER tag for r"));
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    // Parse s
    if der[pos] != 0x02 {
        return Err(anyhow!("invalid DER signature: expected INTEGER tag for s"));
    }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;
    let s_bytes = &der[pos..pos + s_len];

    // Strip leading zero padding and left-pad to 32 bytes.
    let r = strip_and_pad(r_bytes, 32)?;
    let s = strip_and_pad(s_bytes, 32)?;

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    Ok(out)
}

/// Strip DER integer leading-zero padding and left-pad with zeros to `target_len`.
fn strip_and_pad(bytes: &[u8], target_len: usize) -> Result<Vec<u8>> {
    // Strip leading zeros (DER uses them when high bit of first real byte is set).
    let stripped = bytes
        .iter()
        .skip_while(|&&b| b == 0)
        .cloned()
        .collect::<Vec<_>>();
    if stripped.len() > target_len {
        return Err(anyhow!(
            "integer value {} bytes exceeds target {} bytes",
            stripped.len(),
            target_len
        ));
    }
    let mut padded = vec![0u8; target_len - stripped.len()];
    padded.extend_from_slice(&stripped);
    Ok(padded)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::CertStore;
    use sbproxy_platform::MemoryKVStore;

    fn make_store() -> CertStore<MemoryKVStore> {
        CertStore::new(MemoryKVStore::new(0))
    }

    fn synthetic_challenge(kind: &str) -> Challenge {
        Challenge {
            challenge_type: kind.to_string(),
            url: format!("https://acme.example.com/chal/{kind}"),
            token: "tok".to_string(),
            status: "pending".to_string(),
        }
    }

    // --- Multi-challenge selection ---

    #[test]
    fn pick_challenge_honours_preference_order() {
        let challenges = vec![
            synthetic_challenge("dns-01"),
            synthetic_challenge("http-01"),
            synthetic_challenge("tls-alpn-01"),
        ];
        let prefer = vec!["tls-alpn-01".to_string(), "http-01".to_string()];
        let picked = pick_challenge(&challenges, &prefer).unwrap();
        assert_eq!(picked.challenge_type, "tls-alpn-01");
    }

    #[test]
    fn pick_challenge_falls_back_to_http01_when_preference_unmatched() {
        let challenges = vec![
            synthetic_challenge("http-01"),
            synthetic_challenge("dns-01"),
        ];
        // Operator asked for tls-alpn-01 but the authorization does
        // not offer one; we should fall back to http-01.
        let prefer = vec!["tls-alpn-01".to_string()];
        let picked = pick_challenge(&challenges, &prefer).unwrap();
        assert_eq!(picked.challenge_type, "http-01");
    }

    #[test]
    fn pick_challenge_returns_none_when_no_http01_either() {
        let challenges = vec![synthetic_challenge("dns-01")];
        let prefer = vec!["tls-alpn-01".to_string()];
        assert!(pick_challenge(&challenges, &prefer).is_none());
    }

    #[test]
    fn pick_challenge_is_case_insensitive_against_preference() {
        let challenges = vec![synthetic_challenge("http-01")];
        let prefer = vec!["HTTP-01".to_string()];
        assert!(pick_challenge(&challenges, &prefer).is_some());
    }

    #[test]
    fn pick_challenge_empty_preference_falls_through_to_http01() {
        let challenges = vec![
            synthetic_challenge("dns-01"),
            synthetic_challenge("http-01"),
        ];
        let picked = pick_challenge(&challenges, &[]).unwrap();
        assert_eq!(picked.challenge_type, "http-01");
    }

    // --- Account key generate and reload ---

    #[test]
    fn test_account_key_generate_and_reload() {
        let store = make_store();

        // First call: generates a fresh key
        let key1 = AcmeClient::load_or_create_account_key(&store).expect("generate key");
        let pub1 = key1.public_key().as_ref().to_vec();

        // Second call: loads the persisted key
        let key2 = AcmeClient::load_or_create_account_key(&store).expect("reload key");
        let pub2 = key2.public_key().as_ref().to_vec();

        // Both calls must yield the same public key
        assert_eq!(pub1, pub2, "reloaded key differs from generated key");
    }

    #[test]
    fn test_account_key_stored_as_pem() {
        let store = make_store();
        AcmeClient::load_or_create_account_key(&store).expect("generate key");

        let pem_bytes = store
            .get_account_key()
            .unwrap()
            .expect("key should be stored");
        let pem_str = std::str::from_utf8(&pem_bytes).expect("PEM is UTF-8");
        assert!(pem_str.contains("BEGIN PRIVATE KEY"), "PEM header missing");
        assert!(pem_str.contains("END PRIVATE KEY"), "PEM footer missing");
    }

    // --- Key authorization format ---

    #[test]
    fn test_key_authorization_format() {
        let store = make_store();
        let key = AcmeClient::load_or_create_account_key(&store).unwrap();
        let token = "my-challenge-token";
        let ka = AcmeClient::key_authorization(token, &key);

        // Must start with the token
        assert!(ka.starts_with(token), "key auth must start with token");

        // Must have exactly one dot separating token from thumbprint
        let dot_count = ka.chars().filter(|&c| c == '.').count();
        assert_eq!(dot_count, 1, "key auth must have exactly one dot");

        let parts: Vec<&str> = ka.splitn(2, '.').collect();
        assert_eq!(parts[0], token, "token part mismatch");
        assert!(!parts[1].is_empty(), "thumbprint must not be empty");
    }

    // --- PEM roundtrip ---

    #[test]
    fn test_pem_roundtrip() {
        let original = b"\x01\x02\x03\x04\xde\xad\xbe\xef";
        let pem = pkcs8_to_pem(original);
        let decoded = pem_to_pkcs8(pem.as_bytes()).expect("decode PEM");
        assert_eq!(decoded, original, "PEM roundtrip mismatch");
    }

    #[test]
    fn test_pem_has_correct_headers() {
        let pem = pkcs8_to_pem(b"testdata");
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    // --- JWK thumbprint is deterministic ---

    #[test]
    fn test_jwk_thumbprint_deterministic() {
        let store = make_store();
        let key = AcmeClient::load_or_create_account_key(&store).unwrap();
        let t1 = jwk_thumbprint(&key);
        let t2 = jwk_thumbprint(&key);
        assert_eq!(t1, t2, "thumbprint must be deterministic");
    }

    #[test]
    fn test_jwk_thumbprint_different_keys() {
        let store1 = make_store();
        let store2 = make_store();
        let key1 = AcmeClient::load_or_create_account_key(&store1).unwrap();
        let key2 = AcmeClient::load_or_create_account_key(&store2).unwrap();
        // Two independently generated keys should (with overwhelming probability) differ
        let t1 = jwk_thumbprint(&key1);
        let t2 = jwk_thumbprint(&key2);
        assert_ne!(
            t1, t2,
            "different keys should produce different thumbprints"
        );
    }

    #[test]
    fn test_jwk_thumbprint_is_base64url() {
        let store = make_store();
        let key = AcmeClient::load_or_create_account_key(&store).unwrap();
        let thumbprint = jwk_thumbprint(&key);
        // Base64url alphabet: A-Z a-z 0-9 - _  (no padding =)
        assert!(
            thumbprint
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "thumbprint contains non-base64url characters: {thumbprint}"
        );
    }

    // --- AcmeClient::new ---

    #[test]
    fn test_acme_client_new() {
        let client = AcmeClient::new(
            LETS_ENCRYPT_STAGING,
            "test@example.com",
            vec!["http-01".into()],
        );
        assert_eq!(client.directory_url, LETS_ENCRYPT_STAGING);
        assert_eq!(client.email, "test@example.com");
        assert_eq!(client.challenge_types, vec!["http-01"]);
        assert!(client.directory.is_none());
    }

    // --- DER to raw ECDSA signature conversion ---

    #[test]
    fn test_sign_jws_produces_valid_json() {
        let store = make_store();
        let key = AcmeClient::load_or_create_account_key(&store).unwrap();
        let payload = serde_json::json!({"test": "value"});
        let jws = AcmeClient::sign_jws(
            &key,
            "https://example.com/acme/new-order",
            "testnonce",
            &payload,
            None,
        )
        .expect("sign_jws should succeed");

        // Must parse as JSON with required fields.
        let parsed: serde_json::Value = serde_json::from_str(&jws).expect("JWS must be JSON");
        assert!(
            parsed.get("protected").is_some(),
            "JWS must have 'protected'"
        );
        assert!(parsed.get("payload").is_some(), "JWS must have 'payload'");
        assert!(
            parsed.get("signature").is_some(),
            "JWS must have 'signature'"
        );

        // Signature must be non-empty base64url.
        let sig = parsed["signature"].as_str().unwrap();
        assert!(!sig.is_empty(), "signature must not be empty");
        assert!(
            sig.chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "signature must be base64url: {sig}"
        );
    }

    #[test]
    fn test_sign_jws_with_kid_embeds_kid_not_jwk() {
        let store = make_store();
        let key = AcmeClient::load_or_create_account_key(&store).unwrap();
        let payload = serde_json::json!({});
        let jws = AcmeClient::sign_jws(
            &key,
            "https://example.com/acme/order/1",
            "nonce123",
            &payload,
            Some("https://example.com/acme/acct/1"),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();
        // Decode the protected header.
        let protected_b64 = parsed["protected"].as_str().unwrap();
        let protected_bytes = URL_SAFE_NO_PAD.decode(protected_b64).unwrap();
        let protected: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();

        assert!(protected.get("kid").is_some(), "kid header should be set");
        assert!(
            protected.get("jwk").is_none(),
            "jwk should NOT be set when kid is provided"
        );
    }

    #[test]
    fn test_sign_jws_without_kid_embeds_jwk() {
        let store = make_store();
        let key = AcmeClient::load_or_create_account_key(&store).unwrap();
        let payload = serde_json::json!({"termsOfServiceAgreed": true});
        let jws = AcmeClient::sign_jws(
            &key,
            "https://example.com/acme/new-account",
            "nonce456",
            &payload,
            None,
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();
        let protected_b64 = parsed["protected"].as_str().unwrap();
        let protected_bytes = URL_SAFE_NO_PAD.decode(protected_b64).unwrap();
        let protected: serde_json::Value = serde_json::from_slice(&protected_bytes).unwrap();

        assert!(
            protected.get("jwk").is_some(),
            "jwk should be set for new-account"
        );
        assert!(
            protected.get("kid").is_none(),
            "kid should NOT be set without account URL"
        );
    }

    #[test]
    fn test_sign_jws_post_as_get_empty_payload() {
        let store = make_store();
        let key = AcmeClient::load_or_create_account_key(&store).unwrap();
        // POST-as-GET uses an empty string payload, which should encode to "".
        let jws = AcmeClient::sign_jws(
            &key,
            "https://example.com/acme/cert/1",
            "nonce789",
            &serde_json::Value::String(String::new()),
            Some("https://example.com/acme/acct/1"),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();
        let payload = parsed["payload"].as_str().unwrap();
        assert_eq!(payload, "", "POST-as-GET must have empty payload field");
    }

    #[test]
    fn test_der_to_raw_known_signature() {
        // Construct a synthetic DER signature with r=1, s=2 (padded to 32 bytes each).
        // DER: SEQUENCE { INTEGER 0x01, INTEGER 0x02 }
        // 0x30 0x06 0x02 0x01 0x01 0x02 0x01 0x02
        let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let raw = der_to_raw_ecdsa_p256(&der).unwrap();
        assert_eq!(raw.len(), 64, "raw signature must be 64 bytes");
        // r part: 31 zeros followed by 0x01
        assert!(raw[..31].iter().all(|&b| b == 0), "r leading zeros");
        assert_eq!(raw[31], 0x01, "r value");
        // s part: 31 zeros followed by 0x02
        assert!(raw[32..63].iter().all(|&b| b == 0), "s leading zeros");
        assert_eq!(raw[63], 0x02, "s value");
    }
}

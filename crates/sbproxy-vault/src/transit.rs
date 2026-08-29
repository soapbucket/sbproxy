// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! HashiCorp Vault Transit client: encryption as a service (WOR-2568).
//!
//! Every other backend in this crate *reads a secret*. This one deliberately
//! cannot. Transit's contract is that the caller hands over plaintext and
//! gets back ciphertext, or hands over ciphertext and gets back plaintext,
//! and never receives the key that did the work. That difference is the
//! whole of sbproxy's customer-managed-root-of-trust claim: a root of trust
//! that can be read is a root of trust that has already been copied.
//!
//! # Why Transit rather than a `kms://` reference
//!
//! `sbproxy-vault` already resolves `vault://`, `awssm://`, and friends, and
//! a `master_key: vault://...` was always possible. It resolves once, at
//! boot, into process memory, and stays there. Revoking the operator's Vault
//! policy afterwards changes nothing about what this process can decrypt.
//! Transit keeps the external service load bearing at use time, which is the
//! only version of the claim a security team is actually asking about.
//!
//! # Wire contract
//!
//! * `POST {addr}/v1/{mount}/encrypt/{key}` with `{"plaintext": <base64>}`
//!   returns `{"data": {"ciphertext": "vault:v1:<base64>"}}`.
//! * `POST {addr}/v1/{mount}/decrypt/{key}` with `{"ciphertext": ...}`
//!   returns `{"data": {"plaintext": <base64>}}`.
//! * `GET {addr}/v1/{mount}/keys/{key}` is the liveness and authorization
//!   probe: it answers 200 only while the token is valid and the policy
//!   still grants read on the key.
//!
//! The `vault:v1:` prefix carries the key version, which is why a Transit
//! key can be rotated without re-wrapping a single stored envelope: old
//! ciphertext names the version that made it and Vault decrypts against
//! that version until the operator explicitly trims it.
//!
//! # Blocking, and the trace context
//!
//! `ureq`, like every other backend here. Callers that need this from an
//! async context wrap it in `spawn_blocking`, the same way
//! [`crate::resolver`] already does for the read path.
//!
//! Unlike the read backends, these calls sit on the credential-resolution
//! path, so there is a customer request behind them and a trace for them to
//! join. `spawn_blocking` loses the ambient span context across the thread
//! boundary, so the caller captures
//! [`sbproxy_observe::telemetry::outbound_trace_headers`] on the async side
//! and hands the pairs in. That is why every method here takes a `trace`
//! slice rather than reading the context itself: reading it in here would
//! read it on the wrong thread and silently produce nothing.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;

/// How long to wait on a Transit call before giving up.
///
/// Short on purpose. This call sits on the credential-resolution path, and a
/// key service that is not answering in five seconds is an outage the
/// deployment needs to see as a failed resolution rather than as latency.
const TRANSIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Connection settings for a Transit-backed root of trust.
#[derive(Debug, Clone)]
pub struct TransitConfig {
    /// Base address of the Vault (or Vault-compatible) server, for example
    /// `https://vault.internal:8200`. No trailing slash required.
    pub address: String,
    /// Transit mount path. Defaults to `transit`.
    pub mount: String,
    /// Name of the Transit key that wraps sbproxy's data keys. This key is
    /// created and owned by the customer; sbproxy never creates it.
    pub key_name: String,
    /// Already-resolved Vault token. The caller resolves the secret
    /// reference; this type never sees a reference string, so a token that
    /// failed to resolve cannot become the token itself.
    pub token: String,
    /// Optional Vault Enterprise namespace.
    pub namespace: Option<String>,
}

/// A Transit client bound to one mount and one key.
#[derive(Debug, Clone)]
pub struct TransitClient {
    config: TransitConfig,
}

impl TransitClient {
    /// Build a client. Does not contact the server; call
    /// [`Self::liveness`] for that.
    ///
    /// # Errors
    ///
    /// An empty address, mount, key name, or token. Each of those would
    /// otherwise produce a URL or a header that looks plausible and fails
    /// much later, on the credential path, as an opaque 404.
    pub fn new(config: TransitConfig) -> Result<Self> {
        for (field, value) in [
            ("address", config.address.as_str()),
            ("mount", config.mount.as_str()),
            ("key_name", config.key_name.as_str()),
            ("token", config.token.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(anyhow!(
                    "vault transit root of trust: '{field}' is empty; a customer-managed root \
                     needs all of address, mount, key_name, and token"
                ));
            }
        }
        Ok(Self { config })
    }

    /// The operator-facing name of the wrapping key, `<mount>/<key>`.
    /// Persisted onto every envelope this client wraps, so a stored record
    /// names the root that made it.
    pub fn kek_name(&self) -> String {
        format!("{}/{}", self.config.mount, self.config.key_name)
    }

    fn url(&self, operation: &str) -> String {
        format!(
            "{}/v1/{}/{}/{}",
            self.config.address.trim_end_matches('/'),
            self.config.mount.trim_matches('/'),
            operation,
            self.config.key_name
        )
    }

    fn stamp(&self, req: ureq::Request, trace: &[(&'static str, String)]) -> ureq::Request {
        let mut req = req.set("X-Vault-Token", &self.config.token);
        if let Some(ns) = &self.config.namespace {
            req = req.set("X-Vault-Namespace", ns);
        }
        for (name, value) in trace {
            req = req.set(name, value);
        }
        req.timeout(TRANSIT_TIMEOUT)
    }

    /// Encrypt a data key, returning Vault's opaque ciphertext string.
    ///
    /// `trace` is the W3C propagation pairs the caller captured on the
    /// async side; empty for a call with no request behind it.
    ///
    /// # Errors
    ///
    /// Any transport failure, any non-2xx status (403 is the revoked-grant
    /// case and is reported as such), or a response missing
    /// `.data.ciphertext`. The error text never carries the plaintext.
    pub fn wrap(&self, plaintext: &[u8], trace: &[(&'static str, String)]) -> Result<String> {
        let url = self.url("encrypt");
        let body = serde_json::json!({
            "plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext),
        });
        let response = self
            .stamp(
                ureq::post(&url).set("Content-Type", "application/json"),
                trace,
            )
            .send_json(body)
            .map_err(|e| transit_error("encrypt", &url, e))?;
        let json: serde_json::Value = response
            .into_json()
            .context("vault transit: encrypt response was not JSON")?;
        json.get("data")
            .and_then(|d| d.get("ciphertext"))
            .and_then(|c| c.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("vault transit: encrypt response missing .data.ciphertext"))
    }

    /// Decrypt a ciphertext previously produced by [`Self::wrap`].
    ///
    /// `trace` as [`Self::wrap`].
    ///
    /// # Errors
    ///
    /// As [`Self::wrap`], plus a `.data.plaintext` that is not valid
    /// base64.
    pub fn unwrap(&self, ciphertext: &str, trace: &[(&'static str, String)]) -> Result<Vec<u8>> {
        let url = self.url("decrypt");
        let body = serde_json::json!({ "ciphertext": ciphertext });
        let response = self
            .stamp(
                ureq::post(&url).set("Content-Type", "application/json"),
                trace,
            )
            .send_json(body)
            .map_err(|e| transit_error("decrypt", &url, e))?;
        let json: serde_json::Value = response
            .into_json()
            .context("vault transit: decrypt response was not JSON")?;
        let encoded = json
            .get("data")
            .and_then(|d| d.get("plaintext"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow!("vault transit: decrypt response missing .data.plaintext"))?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("vault transit: decrypt returned plaintext that is not base64")
    }

    /// Confirm the key exists and this token is still authorized for it.
    ///
    /// `trace` as [`Self::wrap`]. The background probe passes an empty
    /// slice: it runs on a timer with no request behind it, so there is no
    /// trace for it to join.
    ///
    /// # Errors
    ///
    /// Any transport failure or non-2xx status. A 403 here is the signal an
    /// operator wants: the customer revoked the grant and the deployment's
    /// remaining decrypt capability is bounded by whatever unwrap cache is
    /// still warm.
    pub fn liveness(&self, trace: &[(&'static str, String)]) -> Result<()> {
        let url = self.url("keys");
        self.stamp(ureq::get(&url), trace)
            .call()
            .map_err(|e| transit_error("keys", &url, e))?;
        Ok(())
    }
}

/// Turn a `ureq` failure into an operator-readable error.
///
/// The URL carries no secret (mount, key name, and operation are all
/// operator-chosen non-secrets) and the response body is deliberately not
/// included: Vault error bodies echo request context, and this call's
/// request context is a wrapped data key.
fn transit_error(operation: &str, url: &str, error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(403, _) => anyhow!(
            "vault transit {operation} at {url} was refused with 403: the token is no longer \
             authorized for this key. If the customer revoked sbproxy's grant, this is the \
             expected outcome and credential decryption stops once the unwrap cache lapses."
        ),
        ureq::Error::Status(status, _) => {
            anyhow!("vault transit {operation} at {url} failed with HTTP {status}")
        }
        ureq::Error::Transport(t) => {
            anyhow!("vault transit {operation} at {url} could not be reached: {t}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_incomplete_root_is_refused_at_construction() {
        let base = TransitConfig {
            address: "https://vault.example:8200".to_string(),
            mount: "transit".to_string(),
            key_name: "sbproxy-root".to_string(),
            token: "s.token".to_string(),
            namespace: None,
        };
        assert!(TransitClient::new(base.clone()).is_ok());
        for (name, mutate) in [
            (
                "address",
                (|c: &mut TransitConfig| c.address.clear()) as fn(&mut TransitConfig),
            ),
            ("mount", |c: &mut TransitConfig| c.mount.clear()),
            ("key_name", |c: &mut TransitConfig| c.key_name.clear()),
            ("token", |c: &mut TransitConfig| c.token.clear()),
        ] {
            let mut cfg = base.clone();
            mutate(&mut cfg);
            let err = TransitClient::new(cfg).expect_err("an empty field must be refused");
            assert!(
                err.to_string().contains(name),
                "the refusal must name the empty field: {err}"
            );
        }
    }

    #[test]
    fn the_kek_name_is_mount_and_key() {
        let client = TransitClient::new(TransitConfig {
            address: "https://vault.example:8200/".to_string(),
            mount: "transit".to_string(),
            key_name: "sbproxy-root".to_string(),
            token: "s.token".to_string(),
            namespace: None,
        })
        .expect("valid");
        assert_eq!(client.kek_name(), "transit/sbproxy-root");
        assert_eq!(
            client.url("encrypt"),
            "https://vault.example:8200/v1/transit/encrypt/sbproxy-root"
        );
    }
}

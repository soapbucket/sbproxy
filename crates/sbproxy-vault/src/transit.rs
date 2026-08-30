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
//!
//! Those two are the whole wire surface. The liveness probe is not a third
//! endpoint: it is one `encrypt` followed by one `decrypt` of a fixed
//! non-secret constant, so it needs exactly the grant the credential path
//! needs and no more. It deliberately does **not** read
//! `GET {addr}/v1/{mount}/keys/{key}`, which an earlier version used and
//! which needs `read` on a third path. The least-privilege policy in
//! `docs/key-management.md` grants `update` on encrypt and decrypt and
//! nothing else; a key-read probe fails forever against that policy on a
//! healthy deployment, and passes forever through a revocation that drops
//! encrypt and decrypt while leaving the key readable.
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
///
/// No derived `Debug`: `token` is a live credential and `address` is
/// operator-set and may carry userinfo. This crate hand-writes redacting
/// `Debug` impls for the same value class on `HashiCorpAuth`, and
/// `RootOfTrust` carries a `Debug` bound, so a derive here is one
/// `{:?}` away from being a leak.
#[derive(Clone)]
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
#[derive(Clone)]
pub struct TransitClient {
    config: TransitConfig,
}

/// Redacting `Debug`: mount and key name are operator-chosen non-secrets,
/// the address may carry userinfo, and the token is a live credential.
/// `finish_non_exhaustive` so a later credential-shaped field is omitted by
/// default rather than by somebody remembering to add an arm.
impl std::fmt::Debug for TransitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitConfig")
            .field("mount", &self.mount)
            .field("key_name", &self.key_name)
            .field("address", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for TransitClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitClient")
            .field("config", &self.config)
            .finish()
    }
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
            .map_err(|e| transit_error("encrypt", &self.config.mount, &self.config.key_name, e))?;
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
            .map_err(|e| transit_error("decrypt", &self.config.mount, &self.config.key_name, e))?;
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

    /// Confirm this token is still authorized for the two operations the
    /// credential path actually performs.
    ///
    /// A wrap and an unwrap of a fixed non-secret probe value, not a read
    /// of the key. That distinction is the whole point and it was wrong in
    /// both directions before.
    ///
    /// `GET transit/keys/<name>` needs `read` on `transit/keys/<name>`.
    /// Encrypt and decrypt need `update` on `transit/encrypt/<name>` and
    /// `transit/decrypt/<name>`. Those are different capabilities, and the
    /// least-privilege policy a customer is told to write, the one in
    /// `docs/key-management.md`, grants the second pair and not the first.
    /// So a key-read probe:
    ///
    /// * **fails forever on a healthy deployment.** The 403 maps to
    ///   `Unauthorized`, so every `liveness_interval_secs` the proxy
    ///   dropped its data keys and, as of this branch, every credential the
    ///   root had opened, then re-resolved all of them against the
    ///   customer's Vault. A permanent warn, a permanent
    ///   `probe: "failed_or_never_run"` on the admin surface, and a
    ///   revocation signal that means nothing because it never stops.
    /// * **succeeds forever through a real revocation.** A customer who
    ///   revokes by dropping the encrypt and decrypt paths from the policy,
    ///   which is the narrowest way to do it, leaves the key readable. The
    ///   probe stays green and "or at the next failed liveness probe" never
    ///   fires. The published `unwrap_cache_ttl_secs` bound still holds, so
    ///   nothing is unsafe, but the clause the walkthrough demonstrates is
    ///   dead.
    ///
    /// A round trip closes both. It needs exactly the grant the feature
    /// needs, no more, so it cannot fail on a correctly-scoped policy and
    /// cannot pass on a revoked one.
    ///
    /// The probe value is a constant string, not key material: it is
    /// encrypted and immediately decrypted, and the ciphertext is
    /// discarded. Round-tripping it rather than only encrypting is what
    /// covers `transit/decrypt`, which is the capability a revocation
    /// usually takes first.
    ///
    /// `trace` as [`Self::wrap`]. The background probe passes an empty
    /// slice: it runs on a timer with no request behind it, so there is no
    /// trace for it to join.
    ///
    /// # Errors
    ///
    /// Any transport failure or non-2xx status on either leg. A 403 is the
    /// signal an operator wants: the customer revoked the grant and the
    /// deployment's remaining decrypt capability is bounded by whatever
    /// unwrap cache is still warm.
    pub fn liveness(&self, trace: &[(&'static str, String)]) -> Result<()> {
        let ciphertext = self.wrap(LIVENESS_PROBE_VALUE, trace)?;
        let roundtrip = self.unwrap(&ciphertext, trace)?;
        if roundtrip != LIVENESS_PROBE_VALUE {
            // Not reachable through a correct Transit mount, and worth
            // failing closed on anyway: an endpoint that answers both legs
            // with different bytes is not the key this deployment sealed
            // its credentials under.
            return Err(anyhow!(
                "vault transit liveness on '{}/{}': the probe value did not round-trip; the \
                 endpoint answered but is not the key this deployment wrapped with",
                self.config.mount.trim_matches('/'),
                self.config.key_name
            ));
        }
        Ok(())
    }
}

/// The fixed, non-secret value [`TransitClient::liveness`] round-trips.
///
/// A constant rather than a random draw so the probe is identical on every
/// tick and an operator reading a Vault audit log sees one repeated
/// request rather than traffic they have to account for.
const LIVENESS_PROBE_VALUE: &[u8] = b"sbproxy root-of-trust liveness probe";

/// Why a Transit call could not complete.
///
/// A closed set, and deliberately the only thing about a Transit failure
/// that reaches a message. Two independent sources put the URL in an error
/// here, and `address` is operator-set and never parsed for userinfo:
/// `transit_error` used to format `{url}` itself, and ureq's own
/// `Display for Transport` already ends with the URL it dialed. An operator
/// who fronts Vault with an authenticating proxy and writes
/// `address: https://user:token@vault.internal:8200` would then have that
/// credential land in a per-request warn on the proxy path, a background
/// warn from the liveness probe, and a `POST /admin/credentials` 400 body.
///
/// This workspace already ruled on the identical shape for `reqwest`
/// (`sbproxy-core`'s `ProbeFailureKind`, WOR-2458 fix round, Blocker 1);
/// this is the same treatment for `ureq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitFailure {
    /// The token is no longer authorized for this key. After a customer
    /// revokes sbproxy's grant, this is the expected outcome.
    Unauthorized,
    /// The key or the mount does not exist.
    NotFound,
    /// Any other non-2xx status.
    Status,
    /// The service could not be reached at all.
    Unreachable,
}

impl TransitFailure {
    /// The operator-facing sentence. Never carries the address.
    fn detail(self) -> &'static str {
        match self {
            Self::Unauthorized => {
                "the token is no longer authorized for this key. If the customer revoked \
                 sbproxy's grant, this is the expected outcome and credential decryption stops \
                 once the unwrap cache lapses"
            }
            Self::NotFound => {
                "the mount or key does not exist; check \
                 key_management.crypto.root_of_trust.mount and .key_name"
            }
            Self::Status => "the key service refused the call",
            Self::Unreachable => "the key service could not be reached",
        }
    }
}

/// Classify a `ureq` failure without letting its `Display` reach a message.
///
/// `operation` is one of this module's own literals and `mount` and
/// `key_name` are operator-chosen non-secrets, so those are safe to name.
/// The address is not, and neither is `ureq`'s error text, so neither
/// appears. Taking the two nameable fields as arguments rather than reading
/// `self.config` keeps the address out of reach from inside this function.
fn transit_error(
    operation: &str,
    mount: &str,
    key_name: &str,
    error: ureq::Error,
) -> anyhow::Error {
    let kind = match error {
        ureq::Error::Status(401 | 403, _) => TransitFailure::Unauthorized,
        ureq::Error::Status(404, _) => TransitFailure::NotFound,
        ureq::Error::Status(_, _) => TransitFailure::Status,
        ureq::Error::Transport(_) => TransitFailure::Unreachable,
    };
    anyhow!(
        "vault transit {operation} on '{}/{}': {}",
        mount.trim_matches('/'),
        key_name,
        kind.detail()
    )
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

    /// Registry sentinel for `TransitConfig` and `TransitClient`
    /// (`scripts/secret-debug-registry.txt`).
    ///
    /// The token is a live credential. The address is operator-set and
    /// never parsed, so it may carry userinfo, which is the same reason
    /// it is kept out of `transit_error`.
    #[test]
    fn debug_never_renders_the_transit_token_or_address() {
        let config = TransitConfig {
            address: "https://sbproxy:hvs.MUSTNOTAPPEAR@vault.internal:8200".to_string(),
            mount: "transit".to_string(),
            key_name: "sbproxy-root".to_string(),
            token: "hvs.TOKENMUSTNOTAPPEAR".to_string(),
            namespace: None,
        };
        for rendered in [
            format!("{config:?}"),
            format!("{:?}", TransitClient::new(config.clone()).expect("valid")),
        ] {
            assert!(
                !rendered.contains("hvs.TOKENMUSTNOTAPPEAR"),
                "the token reached Debug: {rendered}"
            );
            assert!(
                !rendered.contains("hvs.MUSTNOTAPPEAR") && !rendered.contains("vault.internal"),
                "the address, which may carry userinfo, reached Debug: {rendered}"
            );
            assert!(
                rendered.contains("transit") && rendered.contains("sbproxy-root"),
                "the mount and key name are operator-chosen non-secrets and must survive, or a \
                 misconfiguration is undiagnosable: {rendered}"
            );
        }
    }

    /// The address never reaches an error, whatever `ureq` says.
    ///
    /// Shaped after `config_soak.rs`'s
    /// `the_probe_failure_detail_is_built_from_a_redacted_url_and_a_bounded_kind`,
    /// which is the precedent this fix copied the enum from and did not
    /// copy the proof from. Without this, restoring `{url}` or the
    /// `ureq::Error` into `transit_error` is a one-line change that
    /// compiles, lints, and passes the whole gate:
    /// `scripts/check-log-url-ratchet.sh`'s raw-request-error counter is
    /// `reqwest`-only by construction, so its `0 (baseline 0)` says
    /// nothing about the four `ureq` clients in this crate.
    ///
    /// The three surfaces this protects are a per-request warn on the
    /// proxy path, the background liveness warn, and the
    /// `POST /admin/credentials` 400 body.
    #[test]
    fn a_transit_error_never_carries_the_address_or_ureq_text() {
        let address = "https://sbproxy:hvs.MUSTNOTAPPEAR@vault.internal:8200";
        // The three status arms of the classifier. These pin the mapping
        // and the `detail()` wording; they do **not** pin the address,
        // and the version of this comment that claimed they did was
        // wrong. `transit_error` takes no `url` and no `self`, and
        // `ureq::Response::new` synthesizes `https://example.com/`, so no
        // arm here can carry the operator's address whatever the body of
        // the function does. The address is pinned by
        // `a_transit_failure_from_a_real_dial_never_carries_the_address`
        // below, which is the one that goes red if `{url}` or ureq's own
        // Display comes back.
        let errors = [
            transit_error(
                "decrypt",
                "transit",
                "sbproxy-root",
                ureq::Error::Status(
                    403,
                    ureq::Response::new(403, "Forbidden", "denied").unwrap(),
                ),
            ),
            transit_error(
                "encrypt",
                "transit",
                "sbproxy-root",
                ureq::Error::Status(404, ureq::Response::new(404, "Not Found", "nope").unwrap()),
            ),
            transit_error(
                "keys",
                "transit",
                "sbproxy-root",
                ureq::Error::Status(500, ureq::Response::new(500, "Boom", "boom").unwrap()),
            ),
        ];
        for error in errors {
            // `{:#}` walks the whole context chain, which is what the
            // proxy warn and the admin body actually render.
            let rendered = format!("{error:#}");
            for forbidden in [
                address,
                "hvs.MUSTNOTAPPEAR",
                "vault.internal",
                "sbproxy:hvs",
                "8200",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "a Transit error leaked '{forbidden}': {rendered}"
                );
            }
            assert!(
                rendered.contains("transit") && rendered.contains("sbproxy-root"),
                "the mount and key name are operator-chosen non-secrets and have to survive, or \
                 the operator cannot tell which key failed: {rendered}"
            );
        }

        // And the classification itself: a revoked grant is the case an
        // operator most needs named, and it must not read as an outage.
        let revoked = format!(
            "{:#}",
            transit_error(
                "decrypt",
                "transit",
                "sbproxy-root",
                ureq::Error::Status(403, ureq::Response::new(403, "Forbidden", "x").unwrap()),
            )
        );
        assert!(
            revoked.contains("no longer authorized"),
            "a 403 is the revoked-grant case and must say so: {revoked}"
        );
    }

    /// A one-shot HTTP server that records each request line and answers
    /// from a canned script of `(status, body)` pairs.
    ///
    /// The status is part of the script rather than a separate "how many
    /// succeed before the failure" count, and that is deliberate. The
    /// count form needs `for i in 0..=ok_count` with `responses[i]` in the
    /// body, which is an inclusive range indexing a shorter slice: clippy
    /// refuses it, and the obvious `.iter().enumerate()` rewrite silently
    /// drops the extra iteration the `..=` existed for. Putting the
    /// failing response in the script removes the index and the trap
    /// together.
    ///
    /// `Connection: close` on every response so `ureq` opens a fresh
    /// connection per call and the accept loop stays one-request-per-accept.
    fn scripted_vault(
        responses: Vec<(u16, String)>,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::channel();
        // Non-blocking with a deadline rather than a blocking accept. A
        // test server that waits forever for a request the code under
        // test stopped making wedges the whole lane, and the code under
        // test is exactly what a revert changes.
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Read, Write};
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            for (status, body) in responses {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                return;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                };
                stream.set_nonblocking(false).expect("blocking stream");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .expect("read timeout");
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    return;
                }
                let mut length = 0usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut payload = vec![0u8; length];
                let _ = reader.read_exact(&mut payload);
                let _ = tx.send(request_line.trim().to_string());
                // Only the statuses this file scripts. An unmapped one
                // is named rather than silently answered "Forbidden",
                // which would make the first 500 or 429 anybody scripts
                // read as a revoked grant.
                let reason = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
                    other => panic!("scripted_vault has no reason phrase for status {other}"),
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    /// The probe's HTTP shape, which is the change this whole round is
    /// named for and which nothing pinned.
    ///
    /// Reverting `liveness()` to `self.url("keys")` plus `ureq::get` left
    /// every test in this file green: construction tests do not dial,
    /// the URL test asserts `url("encrypt")` without saying who calls it,
    /// the `Debug` and error-shape pins do not care about the method, and
    /// the closed-port test fails identically for a GET and a POST. The
    /// only brake was incidental, an unused-const warning that deleting
    /// the const in the same revert clears.
    ///
    /// This asserts the two requests Vault actually receives. A key-read
    /// probe sends one `GET /v1/transit/keys/sbproxy-root` and reddens
    /// every assertion here.
    #[test]
    fn the_liveness_probe_uses_encrypt_and_decrypt_and_not_a_key_read() {
        use base64::Engine as _;
        let ciphertext = "vault:v1:c2Jwcm94eQ==";
        let plaintext = base64::engine::general_purpose::STANDARD.encode(LIVENESS_PROBE_VALUE);
        let (address, requests) = scripted_vault(vec![
            (
                200,
                format!(r#"{{"data":{{"ciphertext":"{ciphertext}"}}}}"#),
            ),
            (200, format!(r#"{{"data":{{"plaintext":"{plaintext}"}}}}"#)),
        ]);

        let client = TransitClient::new(TransitConfig {
            address,
            mount: "transit".to_string(),
            key_name: "sbproxy-root".to_string(),
            token: "hvs.PROBE".to_string(),
            namespace: None,
        })
        .expect("builds");

        client
            .liveness(&[])
            .expect("the scripted round trip succeeds");

        let first = requests.recv().expect("a first request");
        let second = requests.recv().expect("a second request");
        assert_eq!(
            first, "POST /v1/transit/encrypt/sbproxy-root HTTP/1.1",
            "the probe must exercise `update` on encrypt, which is the capability the \
             credential path needs. A key read needs `read` on a third path the \
             least-privilege policy deliberately does not grant"
        );
        assert_eq!(
            second, "POST /v1/transit/decrypt/sbproxy-root HTTP/1.1",
            "and decrypt, which is the capability a narrow revocation drops first. An \
             encrypt-only probe stays green through exactly that revocation"
        );
        assert!(
            requests.try_recv().is_err(),
            "two calls, not three: the probe must not also read the key"
        );
    }

    /// A 403 on either leg is the revoked-grant signal, and it has to
    /// reach the caller as one so the purge arm runs.
    #[test]
    fn a_revoked_grant_on_either_leg_is_reported_as_unauthorized() {
        // The whole script per case, failing response included, so the
        // server helper needs no index and no "how many succeed first"
        // count. `encrypt` is refused on the first call; `decrypt` is
        // refused on the second, after a successful encrypt.
        let denied = r#"{"errors":["permission denied"]}"#.to_string();
        for (label, script) in [
            ("encrypt", vec![(403, denied.clone())]),
            (
                "decrypt",
                vec![
                    (
                        200,
                        r#"{"data":{"ciphertext":"vault:v1:c2Jwcm94eQ=="}}"#.to_string(),
                    ),
                    (403, denied.clone()),
                ],
            ),
        ] {
            let (address, _requests) = scripted_vault(script);
            let client = TransitClient::new(TransitConfig {
                address,
                mount: "transit".to_string(),
                key_name: "sbproxy-root".to_string(),
                token: "hvs.PROBE".to_string(),
                namespace: None,
            })
            .expect("builds");

            let error = client.liveness(&[]).expect_err("a 403 must fail the probe");
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("no longer authorized"),
                "a 403 on the {label} leg is the revoked-grant case and must say so: {rendered}"
            );
        }
    }

    /// The pin that can actually fail, for the property round one's M1 was
    /// about: the operator's `address` must not reach a rendered error.
    ///
    /// The status-arm test above cannot see it. `transit_error`'s
    /// signature is `(operation, mount, key_name, ureq::Error)`, so the
    /// address is not reachable from inside the function, and every
    /// `ureq::Error` it is handed is built from `Response::new`, which
    /// synthesizes `https://example.com/`. Restoring `{url}` to the
    /// `anyhow!`, which is the revert this was supposed to hold, leaves it
    /// green.
    ///
    /// This one goes through the real client against a closed port, so the
    /// `ureq::Error` is a genuine `Transport` whose own `Display` ends
    /// with the URL it dialed, userinfo included. Two reverts redden it:
    /// formatting `{url}` into the message, and appending `{error}` or
    /// `{error:#}` instead of `kind.detail()`.
    ///
    /// `127.0.0.1:1` is refused immediately rather than timing out, so
    /// this costs a connect syscall and no wall clock.
    #[test]
    fn a_transit_failure_from_a_real_dial_never_carries_the_address() {
        let config = TransitConfig {
            address: "http://sbproxy:hvs.DIALMUSTNOTAPPEAR@127.0.0.1:1".to_string(),
            mount: "transit".to_string(),
            key_name: "sbproxy-root".to_string(),
            token: "hvs.TOKENMUSTNOTAPPEAR".to_string(),
            namespace: None,
        };
        let client = TransitClient::new(config).expect("builds");

        // Both legs of the probe and the two credential-path calls, since
        // each maps its own `ureq::Error` through `transit_error`.
        let failures = [
            client.wrap(b"probe", &[]).expect_err("port 1 refuses"),
            client.unwrap("stub", &[]).expect_err("port 1 refuses"),
            client.liveness(&[]).expect_err("port 1 refuses"),
        ];

        for error in failures {
            let rendered = format!("{error:#}");
            for forbidden in [
                "sbproxy:hvs",
                "hvs.DIALMUSTNOTAPPEAR",
                "hvs.TOKENMUSTNOTAPPEAR",
                "127.0.0.1",
                ":1",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "a Transit error from a real dial leaked '{forbidden}': {rendered}"
                );
            }
            assert!(
                rendered.contains("transit") && rendered.contains("sbproxy-root"),
                "the mount and key name still have to survive: {rendered}"
            );
            assert!(
                rendered.contains("could not be reached"),
                "a refused connection is the unreachable case: {rendered}"
            );
        }
    }
}

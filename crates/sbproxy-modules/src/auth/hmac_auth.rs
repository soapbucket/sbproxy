//! WOR-2518: `hmac_auth`, HMAC signed-request authentication.
//!
//! Authenticates machine-to-machine callers that prove possession of a
//! shared secret by signing each request, instead of presenting a
//! static credential that leaks the same value on every call. This is
//! the gap the `digest` (RFC 7616, password-derived challenge) and
//! `bearer` / `api_key` (static possession) providers leave open.
//!
//! # Wire format: RFC 9421, not the draft-cavage `Authorization` shape
//!
//! Apache APISIX's `hmac-auth` plugin, the closest competitive
//! reference, implements the pre-standard draft-cavage HTTP-signatures
//! shape: `Authorization: Signature keyId=...,algorithm=...,headers=...,
//! signature=...` with a `@request-target` pseudo-header and a
//! mandatory `Date` header checked against a clock-skew window
//! (<https://apisix.apache.org/docs/apisix/plugins/hmac-auth/>). The
//! IETF standardized that lineage as RFC 9421 HTTP Message Signatures
//! (<https://www.rfc-editor.org/rfc/rfc9421.html>), which carries the
//! same information in `Signature-Input` / `Signature` headers:
//! `keyid` for the key identifier, the covered-component list for
//! signed-header selection, `@method` / `@path` / `@target-uri`
//! derived components for the request-target binding, and `created` /
//! `expires` for the freshness window. SBproxy already speaks RFC 9421
//! for Web Bot Auth ([`crate::auth::bot_auth`]) and for origin-level
//! `message_signatures` enforcement, so this provider reuses the
//! audited [`sbproxy_middleware::signatures::MessageSignatureVerifier`]
//! (constant-time HMAC comparison via `hmac::Mac::verify_slice`,
//! canonical signature-base reconstruction, algorithm pinning) rather
//! than hand-rolling a second signature scheme.
//!
//! # Algorithm posture
//!
//! `hmac-sha256` only. APISIX offers HMAC-SHA1/SHA256/SHA512; the RFC
//! 9421 algorithm registry (RFC 9421 section 6.2.2) registers exactly
//! one symmetric algorithm, `hmac-sha256`, so pinning it both satisfies
//! the ticket's "SHA256/512 only" floor and refuses SHA-1 by
//! construction. A signature declaring any other `alg` is rejected, and
//! a signature omitting `alg` is rejected outright (the verifier pins
//! the algorithm, so an attacker cannot slip past the pin by dropping
//! the parameter).
//!
//! # Replay defense
//!
//! Timestamp window, per the ticket's analysis and APISIX's model
//! (`clock_skew`, default 300 s): the `created` signature parameter is
//! mandatory, a `created` more than `clock_skew_seconds` in the past
//! is refused as stale, and the underlying verifier refuses a
//! `created` more than `clock_skew_seconds` in the future and any
//! elapsed `expires`. AWS SigV4 (`X-Amz-Date`, 5-15 minute windows)
//! and Stripe webhook signatures (`t=` timestamp, 5 minute default
//! tolerance) use the same defense; GitHub's `X-Hub-Signature-256`
//! omits it and is the weaker shape. A single-use nonce ledger
//! (`bot_auth`'s WOR-502 machinery) can be layered on later without a
//! wire change because RFC 9421 already carries a `nonce` parameter.
//!
//! # Body binding
//!
//! Header-only signatures are the v1 scope (the ticket's explicit
//! call: APISIX's `validate_request_body` equivalent is a follow-up).
//! Verification still fails closed on body coverage: a signature that
//! covers `content-digest` is checked against the body bytes handed to
//! [`HmacAuth::verify`], so at the auth phase (which runs before the
//! body is buffered) a body-bearing request claiming body coverage is
//! refused rather than accepted unverified.

use std::collections::HashMap;

use sbproxy_middleware::signatures::{
    parse_signature_input, MessageSignatureConfig, MessageSignatureVerifier, SignatureAlgorithm,
    VerifyVerdict,
};
use serde::Deserialize;

use crate::auth::CredentialAttrs;

/// Default clock-skew / staleness window in seconds. Matches APISIX
/// `hmac-auth`'s `clock_skew` default of 300, the ticket's stated
/// reference point, and sits inside AWS SigV4's 5-15 minute practice.
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 300;

fn default_clock_skew_seconds() -> u64 {
    DEFAULT_CLOCK_SKEW_SECONDS
}

/// Default covered components every accepted signature must include.
/// `@method` + `@target-uri` bind the verb and the path-and-query, the
/// RFC 9421 equivalent of APISIX's `@request-target` pseudo-header, so
/// a captured signature cannot be replayed against a different verb,
/// path, or query string. Mirrors [`crate::auth::bot_auth`]'s default.
fn default_required_components() -> Vec<String> {
    vec!["@method".to_string(), "@target-uri".to_string()]
}

/// One shared-secret credential: a `key_id` the signer advertises in
/// the `keyid` signature parameter plus the secret it signs with.
/// Structurally the same shape as the `api_key` provider's credential
/// model: secret + flattened per-credential attribution metadata.
///
/// Deliberately not `pub`, and deliberately without a `Debug` derive:
/// the secret must never reach a log line, an error string, or a
/// debug dump. The provider's own `Debug` prints key ids only.
#[derive(Deserialize, Clone)]
struct HmacKeyEntry {
    /// Identifier the signer advertises as the RFC 9421 `keyid`
    /// parameter. Also the per-credential reporting join key stamped
    /// onto the resolved principal.
    key_id: String,
    /// The shared secret. Accepts the same forms as every other
    /// signing-key field: an inline literal, `env:NAME`, `file:PATH`,
    /// `${VAR}`, or a provider URI such as `vault://...`, all resolved
    /// through the central process secret resolver at config compile
    /// time (WOR-2301). The resolved material is decoded hex-first,
    /// then base64, then raw UTF-8 bytes.
    secret: String,
    /// Operator-attached metadata copied onto the matched principal.
    #[serde(flatten, default)]
    attrs: CredentialAttrs,
}

/// Raw config shape for [`HmacAuth::from_config`].
#[derive(Deserialize)]
struct HmacAuthConfig {
    /// Accepted signing keys. At least one entry is required and every
    /// `key_id` must be unique.
    keys: Vec<HmacKeyEntry>,
    /// Replay / freshness window in seconds, applied symmetrically:
    /// `created` may be at most this far in the past (staleness) or
    /// the future (skew). Defaults to 300.
    #[serde(default = "default_clock_skew_seconds")]
    clock_skew_seconds: u64,
    /// Components every accepted signature must cover. Defaults to
    /// `["@method", "@target-uri"]`. An empty list falls back to the
    /// default rather than allowing a signature bound to nothing.
    #[serde(default)]
    required_components: Vec<String>,
}

/// Compiled per-key state: the verifier holding the decoded secret,
/// plus the attribution metadata to stamp on a match.
struct HmacKey {
    verifier: MessageSignatureVerifier,
    attrs: CredentialAttrs,
}

/// Verdict surfaced by [`HmacAuth::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HmacVerdict {
    /// Signature verified against a configured key.
    Verified {
        /// The matched `key_id`.
        key_id: String,
    },
    /// No `Signature-Input` header on the request.
    Missing,
    /// A signature was presented but no configured key matches its
    /// `keyid` parameter.
    UnknownKey {
        /// The `keyid` the request claimed, or `<unset>` when the
        /// header carried none. A key id is an identifier, never the
        /// secret; it is safe to log.
        key_id: String,
    },
    /// A configured key matched but verification failed. `reason` is
    /// safe to log and never carries key material; it must not be
    /// echoed to the client.
    Failed {
        /// The matched `key_id`.
        key_id: String,
        /// Log-safe failure reason from the verifier or the freshness
        /// checks.
        reason: String,
    },
}

/// HMAC signed-request authentication provider (`type: hmac_auth`).
///
/// See the module docs for the scheme choice, algorithm posture, and
/// replay defense. Per-request flow: find the signature whose `keyid`
/// names a configured key, enforce the mandatory-`created` staleness
/// window, then hand the request to the per-key RFC 9421 verifier
/// (algorithm pin, required components, future-`created` / `expires`
/// freshness, canonical base reconstruction, constant-time HMAC
/// comparison).
pub struct HmacAuth {
    /// `key_id` -> compiled key state.
    by_key_id: HashMap<String, HmacKey>,
    /// Symmetric freshness window in seconds.
    clock_skew_seconds: u64,
}

impl std::fmt::Debug for HmacAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys: Vec<&String> = self.by_key_id.keys().collect();
        keys.sort();
        f.debug_struct("HmacAuth")
            .field("key_ids", &keys)
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .finish()
    }
}

impl HmacAuth {
    /// Build the provider from JSON config, resolving every secret
    /// through the central secret resolver and refusing an empty or
    /// duplicate key set. Error strings name the offending `key_id`
    /// and never the configured secret value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: HmacAuthConfig = serde_json::from_value(value)?;
        if cfg.keys.is_empty() {
            anyhow::bail!("hmac_auth requires at least one entry in `keys`");
        }
        let required = if cfg.required_components.is_empty() {
            default_required_components()
        } else {
            cfg.required_components.clone()
        };
        let mut by_key_id = HashMap::with_capacity(cfg.keys.len());
        for entry in cfg.keys {
            if entry.key_id.trim().is_empty() {
                anyhow::bail!("hmac_auth: every key needs a non-empty `key_id`");
            }
            if by_key_id.contains_key(&entry.key_id) {
                anyhow::bail!("hmac_auth: duplicate key_id {:?}", entry.key_id);
            }
            // The verifier resolves `secret` through the process
            // secret resolver and decodes the resolved material; its
            // errors deliberately do not echo the configured value, so
            // this context stays safe to surface.
            let verifier = MessageSignatureVerifier::new(MessageSignatureConfig {
                algorithm: SignatureAlgorithm::HmacSha256,
                key_id: entry.key_id.clone(),
                key: entry.secret.clone(),
                required_components: required.clone(),
                clock_skew_seconds: cfg.clock_skew_seconds,
            })
            .map_err(|e| {
                anyhow::anyhow!(
                    "hmac_auth key {:?}: verifier init failed: {e}",
                    entry.key_id
                )
            })?;
            let mut attrs = entry.attrs.clone();
            // The entry-level `key_id` is the reporting join key; the
            // flattened attrs block never carries one of its own
            // because the outer field consumes the YAML key.
            attrs.key_id = Some(entry.key_id.clone());
            by_key_id.insert(entry.key_id, HmacKey { verifier, attrs });
        }
        Ok(Self {
            by_key_id,
            clock_skew_seconds: cfg.clock_skew_seconds,
        })
    }

    /// Number of configured keys.
    pub fn key_count(&self) -> usize {
        self.by_key_id.len()
    }

    /// Verify the signature on `req` against the configured keys.
    ///
    /// `req` carries the body bytes available to the caller; a
    /// signature covering `content-digest` is checked against exactly
    /// those bytes and fails closed on a mismatch (see the module-level
    /// "Body binding" section).
    pub fn verify(&self, req: &http::Request<bytes::Bytes>) -> HmacVerdict {
        let Some(input) = req.headers().get("signature-input") else {
            return HmacVerdict::Missing;
        };
        let Ok(input_str) = input.to_str() else {
            return HmacVerdict::Missing;
        };
        let entries = match parse_signature_input(input_str) {
            Ok(e) => e,
            Err(e) => {
                // The header did not parse, so no keyid can be
                // attributed; report the unset marker.
                return HmacVerdict::Failed {
                    key_id: "<unset>".to_string(),
                    reason: format!("malformed signature-input: {e}"),
                };
            }
        };
        // Pick the first signature whose keyid names a configured key,
        // mirroring `bot_auth`: RFC 9421 allows several signatures per
        // request so each hop verifies the one addressed to it. This
        // MUST be the same selection rule the per-key verifier applies
        // (first entry in declaration order carrying the matched
        // keyid); checking freshness on one entry and cryptography on
        // another would let a second decoy signature under the same
        // keyid satisfy whichever check the real one fails.
        let matched = entries.iter().find_map(|(_label, entry)| {
            entry
                .params
                .keyid
                .as_deref()
                .filter(|kid| self.by_key_id.contains_key(*kid))
                .map(|kid| (kid.to_string(), entry.params.created))
        });
        let (kid, created) = match matched {
            Some(m) => m,
            None => {
                let claimed = entries
                    .into_iter()
                    .find_map(|(_, e)| e.params.keyid)
                    .unwrap_or_else(|| "<unset>".to_string());
                return HmacVerdict::UnknownKey { key_id: claimed };
            }
        };
        // Replay defense is the created-timestamp window, so a
        // signature without `created` has no freshness bound and is
        // refused outright.
        let Some(created) = created else {
            return HmacVerdict::Failed {
                key_id: kid,
                reason: "missing required `created` parameter".to_string(),
            };
        };

        // Staleness: `created` more than the window in the past is a
        // replay candidate and is refused before any crypto runs. The
        // future direction and `expires` are enforced inside the
        // verifier with the same window.
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(_) => {
                return HmacVerdict::Failed {
                    key_id: kid,
                    reason: "system clock before epoch".to_string(),
                }
            }
        };
        let skew = i64::try_from(self.clock_skew_seconds).unwrap_or(i64::MAX);
        if created < now.saturating_sub(skew) {
            return HmacVerdict::Failed {
                key_id: kid,
                reason: format!(
                    "signature created timestamp is stale: created={created}, window={}s",
                    self.clock_skew_seconds
                ),
            };
        }

        // The kid was matched against the map above; a miss here would
        // mean the map changed mid-call, which it cannot (the provider
        // is immutable after compile). Still fail closed rather than
        // panic so the invariant never becomes a request-path crash.
        let Some(key) = self.by_key_id.get(&kid) else {
            return HmacVerdict::Failed {
                key_id: kid,
                reason: "internal: matched key disappeared".to_string(),
            };
        };
        // Safe-by-default form: a covered `content-digest` is bound to
        // the body bytes on `req` here and now, never deferred.
        match key.verifier.verify_request(req) {
            VerifyVerdict::Ok { .. } => HmacVerdict::Verified { key_id: kid },
            VerifyVerdict::Failed { reason } => HmacVerdict::Failed {
                key_id: kid,
                reason,
            },
        }
    }

    /// Build the attribution principal for a verified `key_id`.
    ///
    /// `sub` is the key id (the signer's identity), the source is
    /// [`sbproxy_plugin::PrincipalSource::Hmac`], and the operator's
    /// per-credential metadata rides along with `attrs.key_id` pinned
    /// to the matched key so per-credential reporting joins work
    /// without an operator-assigned label.
    pub fn principal_for(
        &self,
        key_id: &str,
        tenant_id: sbproxy_plugin::TenantId,
    ) -> Option<sbproxy_plugin::Principal> {
        let key = self.by_key_id.get(key_id)?;
        let mut attrs = key.attrs.to_principal_attrs();
        if attrs.key_id.is_none() {
            attrs.key_id = Some(key_id.to_string());
        }
        Some(sbproxy_plugin::Principal {
            tenant_id,
            sub: key_id.to_string(),
            source: sbproxy_plugin::PrincipalSource::Hmac,
            virtual_key: None,
            attrs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::hmac::{KeyInit as _, Mac as _};
    use base64::Engine as _;

    const SECRET_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn provider(clock_skew: Option<u64>) -> HmacAuth {
        let mut cfg = serde_json::json!({
            "keys": [
                {
                    "key_id": "svc-billing",
                    "secret": SECRET_HEX,
                    "project": "billing",
                    "team": "payments",
                }
            ]
        });
        if let Some(skew) = clock_skew {
            cfg["clock_skew_seconds"] = serde_json::json!(skew);
        }
        HmacAuth::from_config(cfg).expect("provider builds")
    }

    fn now_epoch() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Everything the [`sign`] helper needs to produce a signed
    /// request. A struct rather than positional arguments so each test
    /// names only what it varies.
    struct SignSpec<'a> {
        secret_hex: &'a str,
        key_id: &'a str,
        method: &'a str,
        target_uri: &'a str,
        components: &'a str,
        created: i64,
        extra_headers: &'a [(&'a str, &'a str)],
        body: &'a [u8],
    }

    impl Default for SignSpec<'_> {
        fn default() -> Self {
            SignSpec {
                secret_hex: SECRET_HEX,
                key_id: "svc-billing",
                method: "GET",
                target_uri: "/",
                components: "\"@method\" \"@target-uri\"",
                created: now_epoch(),
                extra_headers: &[],
                body: b"",
            }
        }
    }

    /// Sign a request with the module's exact signature-base
    /// construction, so the tests stay honest if the base builder
    /// shifts. Components and extra headers ride along verbatim.
    fn sign(spec: SignSpec<'_>) -> http::Request<bytes::Bytes> {
        let sig_input = format!(
            "sig1=({});created={};keyid=\"{}\";alg=\"hmac-sha256\"",
            spec.components, spec.created, spec.key_id
        );
        let entries = parse_signature_input(&sig_input).unwrap();
        let (_, entry) = &entries[0];
        let mut builder = http::Request::builder()
            .method(spec.method)
            .uri(spec.target_uri);
        for (name, value) in spec.extra_headers {
            builder = builder.header(*name, *value);
        }
        let req_for_signing = builder
            .body(bytes::Bytes::copy_from_slice(spec.body))
            .unwrap();
        let base =
            sbproxy_middleware::signatures::build_signature_base(&req_for_signing, entry).unwrap();
        let mut mac =
            ::hmac::Hmac::<sha2::Sha256>::new_from_slice(&hex::decode(spec.secret_hex).unwrap())
                .unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let mut builder = http::Request::builder()
            .method(spec.method)
            .uri(spec.target_uri)
            .header("signature-input", &sig_input)
            .header("signature", format!("sig1=:{sig_b64}:"));
        for (name, value) in spec.extra_headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(bytes::Bytes::copy_from_slice(spec.body))
            .unwrap()
    }

    fn default_signed(target_uri: &str) -> http::Request<bytes::Bytes> {
        sign(SignSpec {
            target_uri,
            ..SignSpec::default()
        })
    }

    #[test]
    fn valid_signature_authenticates_and_binds_attribution() {
        let auth = provider(None);
        let req = default_signed("/api/invoices?page=2");
        assert_eq!(
            auth.verify(&req),
            HmacVerdict::Verified {
                key_id: "svc-billing".to_string()
            }
        );
        let principal = auth
            .principal_for("svc-billing", sbproxy_plugin::TenantId::default_tenant())
            .expect("verified key has a principal");
        assert_eq!(principal.sub, "svc-billing");
        assert_eq!(principal.source, sbproxy_plugin::PrincipalSource::Hmac);
        assert_eq!(principal.attrs.project.as_deref(), Some("billing"));
        assert_eq!(principal.attrs.team.as_deref(), Some("payments"));
        assert_eq!(principal.attrs.key_id.as_deref(), Some("svc-billing"));
    }

    #[test]
    fn tampered_path_is_refused() {
        let auth = provider(None);
        let signed = default_signed("/api/invoices");
        // Re-mount the signed headers onto a request for a different
        // path: the reconstructed @target-uri no longer matches.
        let mut req = http::Request::builder()
            .method("GET")
            .uri("/api/admin")
            .body(bytes::Bytes::new())
            .unwrap();
        *req.headers_mut() = signed.headers().clone();
        assert!(
            matches!(auth.verify(&req), HmacVerdict::Failed { .. }),
            "a signature bound to /api/invoices must not authenticate /api/admin"
        );
    }

    #[test]
    fn tampered_method_is_refused() {
        let auth = provider(None);
        let signed = default_signed("/api/invoices");
        let mut req = http::Request::builder()
            .method("DELETE")
            .uri("/api/invoices")
            .body(bytes::Bytes::new())
            .unwrap();
        *req.headers_mut() = signed.headers().clone();
        assert!(
            matches!(auth.verify(&req), HmacVerdict::Failed { .. }),
            "a signature bound to GET must not authenticate DELETE"
        );
    }

    #[test]
    fn tampered_body_is_refused_when_signature_covers_content_digest() {
        let auth = provider(None);
        let body = br#"{"amount":10}"#;
        let digest = sbproxy_middleware::digest::compute_content_digest(
            sbproxy_middleware::digest::Algorithm::Sha256,
            body,
        );
        let req = sign(SignSpec {
            method: "POST",
            target_uri: "/api/invoices",
            components: "\"@method\" \"@target-uri\" \"content-digest\"",
            extra_headers: &[("content-digest", digest.as_str())],
            body,
            ..SignSpec::default()
        });
        assert!(
            matches!(auth.verify(&req), HmacVerdict::Verified { .. }),
            "the untampered body must verify"
        );
        // Same signed headers, different body bytes: the Content-Digest
        // binding must fail closed.
        let mut tampered = http::Request::builder()
            .method("POST")
            .uri("/api/invoices")
            .body(bytes::Bytes::from_static(br#"{"amount":999999}"#))
            .unwrap();
        *tampered.headers_mut() = req.headers().clone();
        assert!(
            matches!(auth.verify(&tampered), HmacVerdict::Failed { .. }),
            "a tampered body must not pass a content-digest-covering signature"
        );
    }

    #[test]
    fn stale_created_timestamp_is_refused() {
        let auth = provider(Some(300));
        let req = sign(SignSpec {
            created: now_epoch() - 301,
            ..SignSpec::default()
        });
        match auth.verify(&req) {
            HmacVerdict::Failed { reason, .. } => {
                assert!(reason.contains("stale"), "reason names staleness: {reason}")
            }
            other => panic!("expected Failed on stale created, got {other:?}"),
        }
    }

    #[test]
    fn created_inside_the_window_is_accepted() {
        let auth = provider(Some(300));
        let req = sign(SignSpec {
            created: now_epoch() - 60,
            ..SignSpec::default()
        });
        assert!(matches!(auth.verify(&req), HmacVerdict::Verified { .. }));
    }

    #[test]
    fn future_created_timestamp_is_refused() {
        let auth = provider(Some(300));
        let req = sign(SignSpec {
            created: now_epoch() + 301,
            ..SignSpec::default()
        });
        assert!(
            matches!(auth.verify(&req), HmacVerdict::Failed { .. }),
            "a future-dated created must be refused"
        );
    }

    #[test]
    fn missing_created_parameter_is_refused() {
        let auth = provider(None);
        // Build a signature whose parameters omit `created` entirely;
        // the signature itself is otherwise valid.
        let sig_input =
            "sig1=(\"@method\" \"@target-uri\");keyid=\"svc-billing\";alg=\"hmac-sha256\"";
        let entries = parse_signature_input(sig_input).unwrap();
        let (_, entry) = &entries[0];
        let req_for_signing = http::Request::builder()
            .method("GET")
            .uri("/")
            .body(bytes::Bytes::new())
            .unwrap();
        let base =
            sbproxy_middleware::signatures::build_signature_base(&req_for_signing, entry).unwrap();
        let mut mac =
            ::hmac::Hmac::<sha2::Sha256>::new_from_slice(&hex::decode(SECRET_HEX).unwrap())
                .unwrap();
        mac.update(base.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("signature-input", sig_input)
            .header("signature", format!("sig1=:{sig_b64}:"))
            .body(bytes::Bytes::new())
            .unwrap();
        match auth.verify(&req) {
            HmacVerdict::Failed { reason, .. } => assert!(
                reason.contains("created"),
                "reason names the missing created parameter: {reason}"
            ),
            other => panic!("expected Failed on missing created, got {other:?}"),
        }
    }

    #[test]
    fn decoy_second_signature_cannot_bypass_the_freshness_check() {
        // Attack shape: sig1 is a captured, validly signed request
        // whose `created` has gone stale; sig2 is a decoy under the
        // same keyid with a fresh `created` and a garbage signature.
        // Freshness and cryptography must be checked on the SAME
        // entry, so this request is refused: the entry the verifier
        // selects (sig1, first in order) is stale.
        let auth = provider(Some(300));
        let real = sign(SignSpec {
            created: now_epoch() - 3600,
            ..SignSpec::default()
        });
        let sig1_input = real.headers()["signature-input"].to_str().unwrap();
        let sig1_value = real.headers()["signature"].to_str().unwrap();
        let fresh = now_epoch();
        let combined_input = format!(
            "{sig1_input}, sig2=(\"@method\" \"@target-uri\");created={fresh};keyid=\"svc-billing\";alg=\"hmac-sha256\""
        );
        let combined_sig = format!("{sig1_value}, sig2=:AAAA:");
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("signature-input", combined_input)
            .header("signature", combined_sig)
            .body(bytes::Bytes::new())
            .unwrap();
        match auth.verify(&req) {
            HmacVerdict::Failed { reason, .. } => assert!(
                reason.contains("stale"),
                "the stale first entry must be the one judged: {reason}"
            ),
            other => panic!("expected Failed on the decoy pair, got {other:?}"),
        }
    }

    #[test]
    fn unknown_key_id_is_refused() {
        let auth = provider(None);
        let req = sign(SignSpec {
            key_id: "some-other-key",
            ..SignSpec::default()
        });
        assert_eq!(
            auth.verify(&req),
            HmacVerdict::UnknownKey {
                key_id: "some-other-key".to_string()
            }
        );
    }

    #[test]
    fn missing_signature_headers_report_missing() {
        let auth = provider(None);
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .body(bytes::Bytes::new())
            .unwrap();
        assert_eq!(auth.verify(&req), HmacVerdict::Missing);
    }

    #[test]
    fn wrong_secret_is_refused() {
        let auth = provider(None);
        let wrong = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let req = sign(SignSpec {
            secret_hex: wrong,
            ..SignSpec::default()
        });
        assert!(matches!(auth.verify(&req), HmacVerdict::Failed { .. }));
    }

    #[test]
    fn non_sha256_algorithm_is_refused() {
        // Posture test: the provider pins hmac-sha256; a signature
        // declaring hmac-sha1 (or anything else) is refused even for a
        // known key.
        let auth = provider(None);
        let created = now_epoch();
        let sig_input = format!(
            "sig1=(\"@method\" \"@target-uri\");created={created};keyid=\"svc-billing\";alg=\"hmac-sha1\""
        );
        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("signature-input", sig_input)
            .header("signature", "sig1=:AAAA:")
            .body(bytes::Bytes::new())
            .unwrap();
        match auth.verify(&req) {
            HmacVerdict::Failed { reason, .. } => {
                assert!(reason.contains("alg"), "reason names the alg pin: {reason}")
            }
            other => panic!("expected Failed on alg mismatch, got {other:?}"),
        }
    }

    #[test]
    fn signature_missing_required_component_is_refused() {
        let auth = provider(None);
        // Sign only @method: the default required set demands
        // @target-uri too, so acceptance would unbind the path.
        let req = sign(SignSpec {
            components: "\"@method\"",
            ..SignSpec::default()
        });
        match auth.verify(&req) {
            HmacVerdict::Failed { reason, .. } => assert!(
                reason.contains("required component"),
                "reason names the missing component: {reason}"
            ),
            other => panic!("expected Failed on missing component, got {other:?}"),
        }
    }

    #[test]
    fn secret_resolves_through_the_process_resolver() {
        // Pin the resolver seam: a `file:` reference must produce the
        // same key material as the identical value inlined, which is
        // only true if resolution goes through the shared resolver
        // before decoding (WOR-2301).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hmac-secret");
        std::fs::write(&path, SECRET_HEX).unwrap();
        let auth = HmacAuth::from_config(serde_json::json!({
            "keys": [
                {"key_id": "svc-billing", "secret": format!("file:{}", path.display())}
            ]
        }))
        .expect("file-referenced secret resolves");
        let req = default_signed("/resolved");
        assert!(
            matches!(auth.verify(&req), HmacVerdict::Verified { .. }),
            "a file:-resolved secret must verify a signature made with the raw material"
        );
    }

    #[test]
    fn unresolvable_provider_uri_is_refused_at_compile() {
        // A vault:// reference with no installed backend must refuse
        // to build rather than silently using the reference string as
        // the key (WOR-2301 / WOR-2283).
        let err = HmacAuth::from_config(serde_json::json!({
            "keys": [
                {"key_id": "svc-billing", "secret": "vault://prod/signing-key"}
            ]
        }))
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("svc-billing"), "error names the key id: {msg}");
    }

    #[test]
    fn config_errors_and_debug_never_echo_the_secret() {
        let marker = "super-secret-material-do-not-log";
        let err = HmacAuth::from_config(serde_json::json!({
            "keys": [
                {"key_id": "a", "secret": marker},
                {"key_id": "a", "secret": marker}
            ]
        }))
        .unwrap_err();
        assert!(!format!("{err:#}").contains(marker));

        let auth = HmacAuth::from_config(serde_json::json!({
            "keys": [{"key_id": "a", "secret": marker}]
        }))
        .unwrap();
        assert!(!format!("{auth:?}").contains(marker));
        assert_eq!(auth.key_count(), 1);
    }

    #[test]
    fn empty_key_set_is_refused() {
        let err = HmacAuth::from_config(serde_json::json!({ "keys": [] })).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn duplicate_key_id_is_refused() {
        let err = HmacAuth::from_config(serde_json::json!({
            "keys": [
                {"key_id": "k", "secret": "s1"},
                {"key_id": "k", "secret": "s2"}
            ]
        }))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate key_id"));
    }
}

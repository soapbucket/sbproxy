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
//! mandatory here, and the underlying verifier enforces the window in
//! both directions with the same `clock_skew_seconds`, refusing a
//! `created` more than that far in the past as stale, one more than
//! that far in the future, and any elapsed `expires`. This module used
//! to re-implement the stale half itself, because the verifier had only
//! the future half; it owns neither now, so `bot_auth` gets the same
//! bound. AWS SigV4 (`X-Amz-Date`, 5-15 minute windows)
//! and Stripe webhook signatures (`t=` timestamp, 5 minute default
//! tolerance) use the same defense; GitHub's `X-Hub-Signature-256`
//! omits it and is the weaker shape. Set `nonce_store: memory` (or
//! inject a [`crate::policy::quote_token::NonceStore`] via [`HmacAuth::with_nonce_store`]) to add
//! exactly-once replay defense inside that window: RFC 9421 already
//! carries a `nonce` parameter, and a wired store requires one and
//! consumes it. Store errors fail closed.
//!
//! # Body binding
//!
//! A signature covering `content-digest` commits to the *header value*.
//! Proving that value describes the bytes the client actually sent
//! takes a second step, and the auth phase cannot take it: it runs
//! before the body has been buffered, so the only bytes it could hand
//! the verifier are none at all.
//!
//! [`HmacAuth::verify`] therefore uses the deferring form of the
//! verifier, and the proxy completes the proof in the request body
//! filter against the complete pre-transform body, answering `401` on a
//! mismatch. That is the same two-step contract
//! [`crate::auth::bot_auth`] uses; the wiring that arms it is
//! `sbproxy_core::server::request_phase::arm_deferred_body_digest_binding`.
//!
//! Covering `content-digest` is opt-in by default. Set
//! `require_body_digest: true` (provider-wide, with a per-key
//! override) to refuse a header-only signature on a request that
//! carries a body. The auth phase detects a body from Content-Length
//! or chunked Transfer-Encoding, matching Apache APISIX
//! `hmac-auth`'s `validate_request_body`. Bodyless requests are not
//! required to cover the digest.
//!
//! Comparing the covered digest against the empty body the auth phase
//! can offer is not a conservative alternative to this. It inverts the
//! check: an honest client sending the true digest of its body is
//! refused, while one that declares the empty-body digest and then
//! sends a body anyway is admitted.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sbproxy_middleware::signatures::{
    parse_signature_input, MessageSignatureConfig, MessageSignatureVerifier, SignatureAlgorithm,
    VerifyVerdict,
};
use serde::Deserialize;

use crate::auth::CredentialAttrs;
use crate::policy::quote_token::{NonceCheck, NonceError, NonceStore};

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
///
/// Permissive on unknown keys while `HmacAuthConfig` around it
/// refuses them (WOR-2181): serde rejects `deny_unknown_fields`
/// together with the flattened `attrs` below at compile time. Do not
/// add it here; it will not build.
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
    /// Per-key override for the provider-wide `require_body_digest`
    /// flag. `None` inherits the provider-wide value.
    #[serde(default)]
    require_body_digest: Option<bool>,
    /// Operator-attached metadata copied onto the matched principal.
    #[serde(flatten, default)]
    attrs: CredentialAttrs,
}

/// Raw config shape for [`HmacAuth::from_config`].
///
/// WOR-2181: unknown keys are refused, so a misspelled
/// `clock_skew_second:` fails the config instead of leaving the
/// replay window at its default. `type:` is stripped by
/// `crate::auth::provider_config_from_value` before this parses.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// When true, a signature that omits `content-digest` on a request
    /// that carries a body is refused. Bodyless requests (GET, or
    /// Content-Length 0 with no Transfer-Encoding) are not required to
    /// cover the digest. Matches Apache APISIX `hmac-auth`'s
    /// `validate_request_body`, which runs only when a body is present
    /// (<https://apisix.apache.org/docs/apisix/plugins/hmac-auth/>).
    /// Default false keeps existing configs header-only. A per-key
    /// `require_body_digest` on a key entry overrides this.
    #[serde(default)]
    require_body_digest: bool,
    /// Optional in-process nonce ledger. `memory` consumes RFC 9421
    /// `nonce` parameters for exactly-once replay defense inside
    /// `clock_skew_seconds`. Omit it to keep timestamp-window-only
    /// replay defense. Durable backends are injected with
    /// [`HmacAuth::with_nonce_store`] (the same seam `bot_auth` uses);
    /// this tree does not take a filesystem or Redis URL here, so a
    /// path-shaped key never reaches the confined-template allowlist.
    #[serde(default)]
    nonce_store: Option<HmacNonceStoreKind>,
}

/// Operator-selectable nonce ledger for `nonce_store`.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HmacNonceStoreKind {
    Memory,
}

/// Compiled per-key state: the verifier holding the decoded secret,
/// plus the attribution metadata to stamp on a match.
struct HmacKey {
    verifier: MessageSignatureVerifier,
    attrs: CredentialAttrs,
    /// Resolved `require_body_digest` for this key (per-key override
    /// or the provider-wide default).
    require_body_digest: bool,
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
    /// Optional single-use nonce ledger. `None` is timestamp-window
    /// only, matching shipped behaviour. When `Some`, a missing nonce
    /// is refused and a replay is `nonce_replay`; a store error is
    /// `nonce_store_error` (fail closed, WOR-1148's lesson).
    nonce_store: Option<Arc<dyn NonceStore>>,
}

impl std::fmt::Debug for HmacAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys: Vec<&String> = self.by_key_id.keys().collect();
        keys.sort();
        f.debug_struct("HmacAuth")
            .field("key_ids", &keys)
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .field("nonce_store", &self.nonce_store.is_some())
            .finish()
    }
}

impl HmacAuth {
    /// Build the provider from JSON config, resolving every secret
    /// through the central secret resolver and refusing an empty or
    /// duplicate key set. Error strings name the offending `key_id`
    /// and never the configured secret value. Unknown keys are refused
    /// (WOR-2181).
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: HmacAuthConfig = crate::auth::provider_config_from_value(value)?;
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
            let require_body_digest = entry.require_body_digest.unwrap_or(cfg.require_body_digest);
            by_key_id.insert(
                entry.key_id,
                HmacKey {
                    verifier,
                    attrs,
                    require_body_digest,
                },
            );
        }
        let nonce_store = match cfg.nonce_store {
            Some(HmacNonceStoreKind::Memory) => Some(Arc::new(HmacMemoryNonceStore::with_ttl(
                cfg.clock_skew_seconds,
            )) as Arc<dyn NonceStore>),
            None => None,
        };
        Ok(Self {
            by_key_id,
            clock_skew_seconds: cfg.clock_skew_seconds,
            nonce_store,
        })
    }

    /// Inject a [`NonceStore`] for exactly-once replay defense inside
    /// the `clock_skew_seconds` window.
    ///
    /// When set, every verified signature must carry an RFC 9421
    /// `nonce` and that value is consumed through
    /// [`NonceStore::check_and_consume_with_expiry`]. A hit is
    /// `nonce_replay`; a store error is `nonce_store_error` (fail
    /// closed). Callers that never inject a store keep today's
    /// timestamp-window-only behaviour, including `from_config`
    /// without `nonce_store: memory`.
    pub fn with_nonce_store(mut self, store: Arc<dyn NonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
    }

    /// Number of configured keys.
    pub fn key_count(&self) -> usize {
        self.by_key_id.len()
    }

    /// Verify the signature on `req` against the configured keys.
    ///
    /// The `content-digest` half of the proof is deferred. This call
    /// verifies the covered components cryptographically; the caller
    /// owns the digest-versus-body comparison and must run it against
    /// the complete request body once that body has arrived. The proxy
    /// does that in the request body filter, so `req` here may carry an
    /// empty body. A caller that skips the second step leaves the
    /// request body unauthenticated. See the module-level "Body
    /// binding" section.
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
                .map(|kid| (kid.to_string(), entry))
        });
        let (kid, entry) = match matched {
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
        // refused outright. This half stays here because RFC 9421 makes
        // `created` optional and the verifier cannot know that this
        // provider requires it.
        //
        // The staleness half used to be re-implemented here, because
        // `check_freshness` in the verifier enforced only the future
        // direction. It enforces both now, with the same
        // `clock_skew_seconds` this provider passes it, so the window is
        // owned in one place and `bot_auth` gets it too.
        if entry.params.created.is_none() {
            return HmacVerdict::Failed {
                key_id: kid,
                reason: "missing required `created` parameter".to_string(),
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
        // Deferring form, matching `bot_auth`. The enforcing
        // `verify_request` would compare a covered `content-digest`
        // against whatever bytes `req` carries, and the auth phase
        // carries none, which refuses the honest client and admits the
        // one declaring the empty-body digest. The body half of the
        // proof is completed in the request body filter instead; see
        // "Body binding" in the module docs.
        match key.verifier.verify_request_deferring_body_binding(req) {
            VerifyVerdict::Ok { .. } => {
                if key.require_body_digest && request_carries_a_body(req) {
                    let covers = entry
                        .components
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case("content-digest"));
                    if !covers {
                        return HmacVerdict::Failed {
                            key_id: kid,
                            reason: "missing required content-digest coverage".to_string(),
                        };
                    }
                }
                if let Err(reason) =
                    self.check_nonce(entry.params.nonce.as_deref(), entry.params.created)
                {
                    return HmacVerdict::Failed {
                        key_id: kid,
                        reason: reason.to_string(),
                    };
                }
                HmacVerdict::Verified { key_id: kid }
            }
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

    /// Consume `nonce` when a store is wired. No store is a no-op so
    /// existing configs stay timestamp-window-only. A wired store
    /// requires a nonce: without one the ledger cannot provide
    /// exactly-once. Store errors fail closed (WOR-1148).
    fn check_nonce(&self, nonce: Option<&str>, created: Option<i64>) -> Result<(), &'static str> {
        let Some(store) = self.nonce_store.as_ref() else {
            return Ok(());
        };
        let Some(nonce) = nonce else {
            return Err("missing required nonce");
        };
        let expires_at = created
            .and_then(|c| u64::try_from(c).ok())
            .unwrap_or(0)
            .saturating_add(self.clock_skew_seconds);
        match store.check_and_consume_with_expiry(nonce, expires_at) {
            Ok(NonceCheck::Fresh) | Ok(NonceCheck::Unknown) => Ok(()),
            Ok(NonceCheck::AlreadyConsumed) => Err("nonce_replay"),
            Err(_) => {
                tracing::warn!("hmac_auth nonce store error; failing closed");
                Err("nonce_store_error")
            }
        }
    }
}

/// Process-local nonce ledger whose entries die at `expires_at`.
///
/// Used when the operator sets `nonce_store: memory`. TTL is the
/// signature's `created` plus `clock_skew_seconds` (passed in via
/// [`NonceStore::check_and_consume_with_expiry`]), so the ledger stays
/// bounded by the same window that already refuses a stale `created`.
#[derive(Clone, Debug)]
struct HmacMemoryNonceStore {
    entries: Arc<parking_lot::Mutex<HashMap<String, u64>>>,
    now_secs: Arc<AtomicU64>,
    ttl_secs: u64,
}

impl HmacMemoryNonceStore {
    fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            entries: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            now_secs: Arc::new(AtomicU64::new(0)),
            ttl_secs,
        }
    }

    #[cfg(test)]
    fn with_clock(now: u64) -> Self {
        Self {
            entries: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            now_secs: Arc::new(AtomicU64::new(now)),
            ttl_secs: DEFAULT_CLOCK_SKEW_SECONDS,
        }
    }

    #[cfg(test)]
    fn set_now(&self, now: u64) {
        self.now_secs.store(now, Ordering::SeqCst);
    }

    fn now(&self) -> u64 {
        let pinned = self.now_secs.load(Ordering::SeqCst);
        if pinned == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        } else {
            pinned
        }
    }
}

impl NonceStore for HmacMemoryNonceStore {
    fn check_and_consume(&self, nonce: &str) -> Result<NonceCheck, NonceError> {
        let expires = self.now().saturating_add(self.ttl_secs);
        self.check_and_consume_with_expiry(nonce, expires)
    }

    fn check_and_consume_with_expiry(
        &self,
        nonce: &str,
        expires_at_unix_secs: u64,
    ) -> Result<NonceCheck, NonceError> {
        let now = self.now();
        let expires_at = if expires_at_unix_secs > now {
            expires_at_unix_secs
        } else {
            now.saturating_add(self.ttl_secs.max(1))
        };
        let mut map = self.entries.lock();
        map.retain(|_, exp| *exp > now);
        if map.get(nonce).is_some_and(|exp| *exp > now) {
            return Ok(NonceCheck::AlreadyConsumed);
        }
        map.insert(nonce.to_string(), expires_at);
        Ok(NonceCheck::Fresh)
    }
}

/// True when the request advertises a body the auth phase can see
/// without buffering it.
///
/// Auth runs before the body is read, so `req.body()` is empty on the
/// live path (`check_auth` synthesizes the request from headers).
/// Content-Length greater than zero and chunked Transfer-Encoding are
/// the signals APISIX uses for `validate_request_body`. A non-empty
/// body on `req` still counts so unit tests that pass bytes through
/// `HmacAuth::verify` stay honest.
fn request_carries_a_body(req: &http::Request<bytes::Bytes>) -> bool {
    if !req.body().is_empty() {
        return true;
    }
    if let Some(len) = req.headers().get(http::header::CONTENT_LENGTH) {
        if let Ok(s) = len.to_str() {
            if s.trim().parse::<u64>().ok().is_some_and(|n| n > 0) {
                return true;
            }
        }
    }
    req.headers()
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::hmac::{KeyInit as _, Mac as _};
    use base64::Engine as _;

    const SECRET_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn provider(clock_skew: Option<u64>) -> HmacAuth {
        provider_from(
            serde_json::json!({
                "keys": [
                    {
                        "key_id": "svc-billing",
                        "secret": SECRET_HEX,
                        "project": "billing",
                        "team": "payments",
                    }
                ]
            }),
            clock_skew,
        )
    }

    fn provider_from(mut cfg: serde_json::Value, clock_skew: Option<u64>) -> HmacAuth {
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
        nonce: Option<&'a str>,
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
                nonce: None,
            }
        }
    }

    /// Sign a request with the module's exact signature-base
    /// construction, so the tests stay honest if the base builder
    /// shifts. Components and extra headers ride along verbatim.
    fn sign(spec: SignSpec<'_>) -> http::Request<bytes::Bytes> {
        let nonce_param = spec
            .nonce
            .map(|n| format!(";nonce=\"{n}\""))
            .unwrap_or_default();
        let sig_input = format!(
            "sig1=({});created={};keyid=\"{}\";alg=\"hmac-sha256\"{nonce_param}",
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

    /// The provider verifies headers and hands the body half back.
    ///
    /// This test used to assert that `verify` itself refused a tampered
    /// body. It cannot: `verify` runs in the auth phase, which has no
    /// body to compare against, and the bytes on `req` there are always
    /// empty. Asserting refusal at this layer is what let the shipped
    /// build compare a covered digest against zero bytes.
    ///
    /// So the contract this pins is the deferral itself: the signature
    /// verifies on its covered headers regardless of the body carried
    /// here, and the digest-versus-body comparison the caller owes is
    /// the thing that separates the honest body from the tampered one.
    /// The enforcement is pinned end to end in `sbproxy-core` by
    /// `server::tests::hmac_auth_binds_a_body_covering_signature_to_the_body_that_arrives`.
    #[test]
    fn content_digest_binding_is_deferred_to_the_caller() {
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
            "the covered headers must verify"
        );

        // The auth phase hands the verifier an empty body, so a
        // provider that bound the digest here would refuse this.
        let mut empty_bodied = http::Request::builder()
            .method("POST")
            .uri("/api/invoices")
            .body(bytes::Bytes::new())
            .unwrap();
        *empty_bodied.headers_mut() = req.headers().clone();
        assert!(
            matches!(auth.verify(&empty_bodied), HmacVerdict::Verified { .. }),
            "verification must not depend on body bytes this phase does not have"
        );

        // What the caller owes, and what it catches.
        const TAMPERED: &[u8] = br#"{"amount":999999}"#;
        assert!(
            sbproxy_middleware::digest::verify_content_digest(&digest, body),
            "the caller's check admits the body the signature covered"
        );
        assert!(
            !sbproxy_middleware::digest::verify_content_digest(&digest, TAMPERED),
            "the caller's check refuses a substituted body"
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

    /// WOR-2547: a POST with a Content-Length (the production auth-phase
    /// shape: headers present, body not yet buffered) and a header-only
    /// signature must be refused when `require_body_digest` is on.
    fn header_only_post_advertising_a_body() -> http::Request<bytes::Bytes> {
        sign(SignSpec {
            method: "POST",
            target_uri: "/api/invoices",
            extra_headers: &[("content-length", "13")],
            body: b"",
            ..SignSpec::default()
        })
    }

    #[test]
    fn require_body_digest_refuses_a_header_only_signature_when_the_request_carries_a_body() {
        let auth = provider_from(
            serde_json::json!({
                "require_body_digest": true,
                "keys": [{ "key_id": "svc-billing", "secret": SECRET_HEX }]
            }),
            None,
        );
        match auth.verify(&header_only_post_advertising_a_body()) {
            HmacVerdict::Failed { reason, key_id } => {
                assert_eq!(key_id, "svc-billing");
                assert!(
                    reason.contains("content-digest"),
                    "reason names the missing coverage: {reason}"
                );
                assert!(
                    !reason.contains(SECRET_HEX),
                    "reason must never echo key material: {reason}"
                );
            }
            other => panic!("expected Failed on missing body coverage, got {other:?}"),
        }
    }

    #[test]
    fn require_body_digest_admits_a_content_digest_covering_signature() {
        let auth = provider_from(
            serde_json::json!({
                "require_body_digest": true,
                "keys": [{ "key_id": "svc-billing", "secret": SECRET_HEX }]
            }),
            None,
        );
        let body = br#"{"amount":10}"#;
        let digest = sbproxy_middleware::digest::compute_content_digest(
            sbproxy_middleware::digest::Algorithm::Sha256,
            body,
        );
        let req = sign(SignSpec {
            method: "POST",
            target_uri: "/api/invoices",
            components: "\"@method\" \"@target-uri\" \"content-digest\"",
            extra_headers: &[
                ("content-digest", digest.as_str()),
                ("content-length", "13"),
            ],
            body: b"",
            ..SignSpec::default()
        });
        assert!(
            matches!(auth.verify(&req), HmacVerdict::Verified { .. }),
            "covering content-digest satisfies the knob; the body half is deferred"
        );
    }

    #[test]
    fn require_body_digest_does_not_apply_to_a_bodyless_request() {
        let auth = provider_from(
            serde_json::json!({
                "require_body_digest": true,
                "keys": [{ "key_id": "svc-billing", "secret": SECRET_HEX }]
            }),
            None,
        );
        let req = default_signed("/api/invoices");
        assert!(
            matches!(auth.verify(&req), HmacVerdict::Verified { .. }),
            "APISIX validates only when a body is present; GET without one stays header-only"
        );
    }

    #[test]
    fn require_body_digest_off_admits_a_header_only_signature_on_a_bodied_request() {
        let auth = provider(None);
        assert!(
            matches!(
                auth.verify(&header_only_post_advertising_a_body()),
                HmacVerdict::Verified { .. }
            ),
            "default false must keep today's header-only POST behaviour"
        );
    }

    #[test]
    fn require_body_digest_per_key_override_wins() {
        let auth = provider_from(
            serde_json::json!({
                "require_body_digest": true,
                "keys": [
                    {
                        "key_id": "svc-billing",
                        "secret": SECRET_HEX,
                        "require_body_digest": false
                    }
                ]
            }),
            None,
        );
        assert!(
            matches!(
                auth.verify(&header_only_post_advertising_a_body()),
                HmacVerdict::Verified { .. }
            ),
            "a per-key false must override the provider-wide true"
        );
    }

    fn signed_with_nonce(nonce: &str) -> http::Request<bytes::Bytes> {
        sign(SignSpec {
            nonce: Some(nonce),
            ..SignSpec::default()
        })
    }

    #[test]
    fn nonce_store_first_presentation_verifies() {
        let auth = provider(None).with_nonce_store(std::sync::Arc::new(
            crate::policy::quote_token::InMemoryNonceStore::new(),
        )
            as std::sync::Arc<dyn crate::policy::quote_token::NonceStore>);
        assert!(matches!(
            auth.verify(&signed_with_nonce("n-first")),
            HmacVerdict::Verified { .. }
        ));
    }

    #[test]
    fn nonce_store_refuses_a_signature_without_a_nonce() {
        let auth = provider(None).with_nonce_store(std::sync::Arc::new(
            crate::policy::quote_token::InMemoryNonceStore::new(),
        )
            as std::sync::Arc<dyn crate::policy::quote_token::NonceStore>);
        match auth.verify(&default_signed("/")) {
            HmacVerdict::Failed { reason, .. } => {
                assert!(
                    reason.contains("missing required nonce"),
                    "a wired store cannot provide exactly-once without a nonce: {reason}"
                );
            }
            other => panic!("expected Failed on missing nonce, got {other:?}"),
        }
    }

    #[test]
    fn nonce_store_replay_inside_the_window_is_refused() {
        let auth = provider(None).with_nonce_store(std::sync::Arc::new(
            crate::policy::quote_token::InMemoryNonceStore::new(),
        )
            as std::sync::Arc<dyn crate::policy::quote_token::NonceStore>);
        let req = signed_with_nonce("n-replay");
        assert!(matches!(auth.verify(&req), HmacVerdict::Verified { .. }));
        match auth.verify(&req) {
            HmacVerdict::Failed { reason, .. } => {
                assert!(
                    reason.contains("nonce_replay"),
                    "reason names the replay: {reason}"
                );
                assert!(
                    !reason.contains(SECRET_HEX),
                    "reason must never echo key material: {reason}"
                );
            }
            other => panic!("expected Failed on nonce replay, got {other:?}"),
        }
    }

    #[test]
    fn no_nonce_store_admits_a_replay_inside_the_window() {
        let auth = provider(None);
        let req = signed_with_nonce("n-window-only");
        assert!(matches!(auth.verify(&req), HmacVerdict::Verified { .. }));
        assert!(
            matches!(auth.verify(&req), HmacVerdict::Verified { .. }),
            "without a store the only replay defense is the created window"
        );
    }

    #[derive(Debug)]
    struct FailingNonceStore;

    impl crate::policy::quote_token::NonceStore for FailingNonceStore {
        fn check_and_consume(
            &self,
            _nonce: &str,
        ) -> Result<crate::policy::quote_token::NonceCheck, crate::policy::quote_token::NonceError>
        {
            Err(crate::policy::quote_token::NonceError::new(
                "injected store failure",
            ))
        }
    }

    #[test]
    fn nonce_store_error_fails_closed() {
        let auth = provider(None).with_nonce_store(std::sync::Arc::new(FailingNonceStore)
            as std::sync::Arc<dyn crate::policy::quote_token::NonceStore>);
        match auth.verify(&signed_with_nonce("n-store-err")) {
            HmacVerdict::Failed { reason, .. } => {
                assert!(
                    reason.contains("nonce_store_error"),
                    "store errors fail closed: {reason}"
                );
                assert!(
                    !reason.contains("injected store failure"),
                    "client-facing reason must not echo the backend error: {reason}"
                );
            }
            other => panic!("expected Failed on store error, got {other:?}"),
        }
    }

    #[test]
    fn nonce_store_memory_config_wires_the_ledger() {
        let auth = provider_from(
            serde_json::json!({
                "nonce_store": "memory",
                "keys": [{ "key_id": "svc-billing", "secret": SECRET_HEX }]
            }),
            None,
        );
        let req = signed_with_nonce("n-cfg-memory");
        assert!(matches!(auth.verify(&req), HmacVerdict::Verified { .. }));
        match auth.verify(&req) {
            HmacVerdict::Failed { reason, .. } => {
                assert!(reason.contains("nonce_replay"), "{reason}")
            }
            other => panic!("memory nonce_store must refuse the replay, got {other:?}"),
        }
    }

    #[test]
    fn nonce_entry_expires_on_the_skew_window_boundary() {
        let store = HmacMemoryNonceStore::with_clock(1_700_000_000);
        assert_eq!(
            store
                .check_and_consume_with_expiry("n-ttl", 1_700_000_300)
                .expect("store answers"),
            crate::policy::quote_token::NonceCheck::Fresh
        );
        assert_eq!(
            store
                .check_and_consume_with_expiry("n-ttl", 1_700_000_300)
                .expect("store answers"),
            crate::policy::quote_token::NonceCheck::AlreadyConsumed
        );
        store.set_now(1_700_000_301);
        assert_eq!(
            store
                .check_and_consume_with_expiry("n-ttl", 1_700_000_601)
                .expect("store answers"),
            crate::policy::quote_token::NonceCheck::Fresh,
            "after clock_skew_seconds the ledger must forget the nonce"
        );
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

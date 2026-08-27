//! WOR-2667: `kya` provider, Know Your Agent token verification.
//!
//! An AI agent presents a token its identity provider issued, in the
//! `X-Skyfire-KYA` request header, and the proxy verifies it: signed by
//! a key in the issuer's JWKS, issued by an issuer on the operator's
//! allowlist, not expired, addressed to this gateway, and not on the
//! issuer's revocation list. What comes back is not just "is this
//! caller allowed" but *who the caller is*: the agent's identifier, the
//! vendor operating it, the class of agent it claims to be, and,
//! optionally, how much the agent can spend.
//!
//! # Why the spend balance is the interesting half
//!
//! An agent identity that carries a balance lets an origin refuse a
//! caller that cannot pay before the request reaches the upstream that
//! would bill for it. `min_kyab_balance` is that gate: a token whose
//! balance is below the configured floor is refused with a `402
//! Payment Required`, which is the status a paying client can act on,
//! rather than the `401` that tells it to go get a new credential it
//! does not need. Leave `min_kyab_balance` unset and the balance is
//! carried as advisory metadata for policy scripts to read
//! (`request.kya.kyab_balance.amount`) without gating anything.
//!
//! # Where the verdict lands
//!
//! Every verdict, not just the accepting one, is stamped onto the
//! per-request context as `request.kya.verdict` for CEL, Lua,
//! JavaScript, and WASM policies, and it feeds the trust tier: a
//! verified token earns `strong`, a presented-and-rejected one drops
//! the request to `suspicious`, and a directory the proxy could not
//! reach stays neutral because a fetch failure is not evidence about
//! the caller. See [`crate::auth::trust_tier`].
//!
//! # Security posture
//!
//! * **The issuer allowlist is checked before any network fetch.** A
//!   token naming an issuer the operator did not list is refused
//!   without the proxy dialing the URL the token asked it to, so a
//!   forged `iss` is not a way to make the gateway fetch arbitrary
//!   hosts.
//! * **Issuer URLs must be `https://`.** The JWKS is the root of trust
//!   for every token from that issuer; fetching it over plaintext would
//!   let anyone on the path mint accepted tokens.
//! * **`alg` is pinned to ES256 and RS256** at decode time, so a token
//!   cannot talk the verifier down to `none` or to a symmetric
//!   algorithm keyed on the public key.
//! * **The audience must name this gateway.** `aud` has to contain the
//!   request's hostname or the literal `*`, so a token minted for a
//!   different gateway does not verify here.
//! * **Revocation is checked on every verification**, against the
//!   issuer's published denylist, cached with the same stale-grace
//!   window as the JWKS.
//! * **A fetch failure fails closed by default.** `fail_open: true`
//!   inverts it for deployments that would rather serve than refuse
//!   while an issuer is down; the verdict is still recorded as
//!   `directory_unavailable`, never as `verified`, so the metric does
//!   not claim a verification that did not happen.
//!
//! # Caching, and what it cannot do
//!
//! The JWKS and the denylist are cached per issuer for
//! `jwks_refresh_interval_secs`, with a `stale_grace_secs` window in
//! which the last good copy still serves if a refresh fails. Verdicts
//! themselves are *not* cached: a token is verified on every request,
//! because a cached verdict is a revocation the proxy has decided not
//! to see. Verification is local work once the JWKS is warm.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Request header carrying the KYA token.
const KYA_HEADER: &str = "x-skyfire-kya";

/// Default JWKS and denylist refresh interval, in seconds.
pub const DEFAULT_REFRESH_SECS: u64 = 3600;

/// Shortest JWKS refresh interval an operator may configure.
///
/// Below this the gateway is polling the issuer rather than caching it,
/// and an issuer's rate limiter is the thing that finds out.
const MIN_REFRESH_SECS: u64 = 300;

/// Longest JWKS refresh interval an operator may configure. Past a day
/// a rotated key is a day of refusals.
const MAX_REFRESH_SECS: u64 = 86_400;

/// Default stale-grace window, in seconds.
///
/// While an issuer is unreachable, the last good JWKS keeps verifying
/// for this long past its refresh interval. A day is the window the
/// Web Bot Auth directory cache already uses for the same problem
/// ([`crate::auth::bot_auth_directory`]), and the two are kept the same on
/// purpose: an operator should not have to learn two answers to "how
/// long does a directory outage take to become a refusal".
pub const DEFAULT_STALE_GRACE_SECS: u64 = 86_400;

/// Deadline for one JWKS or denylist fetch.
pub const FETCH_DEADLINE: Duration = Duration::from_secs(2);

/// Largest JWKS or denylist document the verifier will parse.
const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

/// Clock skew tolerated on `exp` and `iat`, in seconds.
const CLOCK_SKEW_SECS: u64 = 2;

/// Advisory spend balance carried in a KYA token.
///
/// Defined here rather than reusing a wallet type: this is the
/// issuer's number about the agent's account with the issuer, not a
/// balance the proxy holds or settles against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KyabBalance {
    /// Amount in the smallest unit of `currency`.
    pub amount: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// RFC 3339 instant the balance stops being meaningful.
    pub expires_at: String,
}

/// What verifying one token concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KyaVerdict {
    /// The token verified end to end.
    Verified(Box<VerifiedAgent>),
    /// No token was presented.
    Missing,
    /// The token failed verification for a reason that is neither
    /// expiry nor revocation. `reason` is a closed label.
    Invalid {
        /// Closed reason label, safe for a metric and a log line.
        reason: &'static str,
    },
    /// `exp` is in the past. Split out from `Invalid` so an agent gets
    /// a "refresh your token" signal rather than a generic refusal.
    Expired,
    /// The token's `jti` is on the issuer's denylist.
    Revoked,
    /// The token verified but its balance is below the configured
    /// floor.
    InsufficientBalance {
        /// The floor the origin requires, in the smallest currency
        /// unit. Operator config, safe to return to the caller.
        required: u64,
    },
    /// The JWKS or denylist could not be fetched and no cached copy is
    /// still inside its stale-grace window.
    DirectoryUnavailable,
}

/// The identity a verified token establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgent {
    /// The issuer's identifier for the agent.
    pub agent_id: String,
    /// Operator-facing vendor name (`OpenAI`, `Anthropic`, ...).
    pub vendor: String,
    /// The class of agent the token claims (`crawler`, `assistant`).
    pub agent_class: String,
    /// KYA specification version the token was minted under.
    pub kya_version: String,
    /// The token's `sub` claim: the issuer's stable subject.
    pub sub: String,
    /// Advisory balance, when the token carried one.
    pub kyab_balance: Option<KyabBalance>,
}

impl KyaVerdict {
    /// Stable metric and scripting label for this verdict.
    ///
    /// The values are the closed set
    /// `crates/sbproxy-core/src/context.rs` documents for
    /// `request.kya.verdict`, plus `insufficient_balance`, so a policy
    /// script and the `sbproxy_kya_verdicts_total` metric read the same
    /// vocabulary.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Verified(_) => "verified",
            Self::Missing => "missing",
            Self::Invalid { .. } => "invalid",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::InsufficientBalance { .. } => "insufficient_balance",
            Self::DirectoryUnavailable => "directory_unavailable",
        }
    }

    /// Finer-grained reason, for the log line rather than the label.
    ///
    /// Kept off the metric on purpose: `unsupported_alg`,
    /// `untrusted_issuer`, `signature_invalid`, and the rest are useful
    /// in a log and would multiply the series set for a question an
    /// operator asks once.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Invalid { reason } => reason,
            other => other.metric_label(),
        }
    }
}

/// One issuer on the operator's allowlist.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KyaIssuer {
    /// Issuer URL, matched verbatim against the token's `iss` claim.
    pub url: String,
    /// How long a fetched JWKS or denylist stays fresh, in seconds.
    /// Clamped to `[MIN_REFRESH_SECS, MAX_REFRESH_SECS]`.
    #[serde(default = "default_refresh_secs")]
    pub jwks_refresh_interval_secs: u64,
    /// How long past the refresh interval a cached copy still serves
    /// while the issuer is unreachable.
    #[serde(default = "default_stale_grace_secs")]
    pub stale_grace_secs: u64,
}

fn default_refresh_secs() -> u64 {
    DEFAULT_REFRESH_SECS
}

fn default_stale_grace_secs() -> u64 {
    DEFAULT_STALE_GRACE_SECS
}

impl KyaIssuer {
    fn validate(&self) -> anyhow::Result<()> {
        if !self.url.starts_with("https://") {
            anyhow::bail!(
                "kya issuer url must be https://; the JWKS fetched from it is the \
                 root of trust for every token that issuer signs"
            );
        }
        Ok(())
    }

    fn refresh_interval(&self) -> Duration {
        Duration::from_secs(
            self.jwks_refresh_interval_secs
                .clamp(MIN_REFRESH_SECS, MAX_REFRESH_SECS),
        )
    }

    fn jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.url.trim_end_matches('/'))
    }

    fn denylist_url(&self) -> String {
        format!(
            "{}/.well-known/kya-denylist.json",
            self.url.trim_end_matches('/')
        )
    }
}

/// A cached document plus the two instants that decide whether it may
/// still be served.
#[derive(Debug, Clone)]
struct CachedDocument<T> {
    value: T,
    fetched_at: Instant,
    fresh_until: Instant,
}

/// KYA token verifier.
pub struct KyaVerifier {
    issuers: Vec<KyaIssuer>,
    /// Balance floor, in the smallest currency unit. `None` leaves the
    /// balance advisory.
    pub min_kyab_balance: Option<u64>,
    /// When true, an unreachable issuer admits the request instead of
    /// refusing it.
    pub fail_open: bool,
    jwks_cache: RwLock<HashMap<String, CachedDocument<JwkSet>>>,
    denylist_cache: RwLock<HashMap<String, CachedDocument<HashSet<String>>>>,
    client: reqwest::Client,
}

impl std::fmt::Debug for KyaVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KyaVerifier")
            .field("issuers", &self.issuers.len())
            .field("min_kyab_balance", &self.min_kyab_balance)
            .field("fail_open", &self.fail_open)
            .finish()
    }
}

/// The claims a KYA token carries. Unknown claims are ignored: an
/// issuer adding a claim must not break verification.
#[derive(Debug, Deserialize)]
struct KyaClaims {
    #[serde(default)]
    jti: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    vendor: String,
    #[serde(default)]
    agent_class: String,
    #[serde(default)]
    kya_version: String,
    #[serde(default)]
    kyab_balance: Option<KyabBalance>,
}

impl KyaVerifier {
    /// Build a verifier from its `authentication:` block.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawConfig {
            issuers: Vec<KyaIssuer>,
            #[serde(default)]
            fail_open: bool,
            #[serde(default)]
            min_kyab_balance: Option<u64>,
        }

        let raw: RawConfig = super::provider_config_from_value(value)?;
        if raw.issuers.is_empty() {
            anyhow::bail!(
                "kya requires at least one entry under `issuers:`; with none, \
                 every token names an issuer that is not on the allowlist"
            );
        }
        for issuer in &raw.issuers {
            issuer.validate()?;
        }
        let client = reqwest::Client::builder()
            .timeout(FETCH_DEADLINE)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| anyhow::anyhow!("kya client build failed: {e}"))?;
        Ok(Self {
            issuers: raw.issuers,
            min_kyab_balance: raw.min_kyab_balance,
            fail_open: raw.fail_open,
            jwks_cache: RwLock::new(HashMap::new()),
            denylist_cache: RwLock::new(HashMap::new()),
            client,
        })
    }

    /// Pull the token out of a request's headers.
    pub fn extract_token(headers: &http::HeaderMap) -> Option<&str> {
        let value = headers.get(KYA_HEADER)?.to_str().ok()?.trim();
        (!value.is_empty()).then_some(value)
    }

    /// Verify the token a request presented.
    ///
    /// `hostname` is the request's `Host`, without a port, and is what
    /// the token's `aud` claim has to name. Records the verdict on
    /// `sbproxy_kya_verdicts_total` before returning.
    pub async fn verify(&self, headers: &http::HeaderMap, hostname: &str) -> KyaVerdict {
        let verdict = self
            .verify_token(Self::extract_token(headers), hostname)
            .await;
        sbproxy_observe::metrics::record_kya_verdict(verdict.metric_label());
        verdict
    }

    /// Verify one token. Public so a caller holding the token already
    /// (a test, a replay tool) does not have to synthesize headers.
    pub async fn verify_token(&self, token: Option<&str>, hostname: &str) -> KyaVerdict {
        let Some(token) = token else {
            return KyaVerdict::Missing;
        };

        let header = match decode_header(token) {
            Ok(header) => header,
            Err(_) => {
                return KyaVerdict::Invalid {
                    reason: "malformed",
                }
            }
        };
        if !matches!(header.alg, Algorithm::ES256 | Algorithm::RS256) {
            return KyaVerdict::Invalid {
                reason: "unsupported_alg",
            };
        }
        let Some(kid) = header.kid.as_deref() else {
            return KyaVerdict::Invalid {
                reason: "malformed",
            };
        };

        // Read `iss` without verifying anything, purely to pick the
        // issuer entry. Nothing from this peek is trusted past the
        // allowlist lookup: the signature check below is against the
        // key set of the issuer the operator listed, so a forged `iss`
        // can only ever select a key set that will refuse it.
        let Some(iss) = peek_issuer(token) else {
            return KyaVerdict::Invalid {
                reason: "malformed",
            };
        };
        let Some(issuer) = self.issuers.iter().find(|issuer| issuer.url == iss) else {
            return KyaVerdict::Invalid {
                reason: "untrusted_issuer",
            };
        };

        let jwks = match self.jwks(issuer).await {
            Some(jwks) => jwks,
            None => return KyaVerdict::DirectoryUnavailable,
        };
        let Some(jwk) = jwks.find(kid) else {
            return KyaVerdict::Invalid {
                reason: "unknown_kid",
            };
        };
        let key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e).ok(),
            AlgorithmParameters::EllipticCurve(ec) => {
                DecodingKey::from_ec_components(&ec.x, &ec.y).ok()
            }
            AlgorithmParameters::OctetKey(_) | AlgorithmParameters::OctetKeyPair(_) => None,
        };
        let Some(key) = key else {
            return KyaVerdict::Invalid {
                reason: "unsupported_key",
            };
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(std::slice::from_ref(&issuer.url));
        // `*` is the wildcard audience the KYA profile defines for a
        // token minted for no particular gateway.
        validation.set_audience(&[hostname, "*"]);
        validation.leeway = CLOCK_SKEW_SECS;
        validation.validate_exp = true;

        let decoded = match decode::<KyaClaims>(token, &key, &validation) {
            Ok(decoded) => decoded,
            Err(error) => return classify_jwt_error(&error),
        };

        let denylist = match self.denylist(issuer).await {
            Some(denylist) => denylist,
            None => return KyaVerdict::DirectoryUnavailable,
        };
        if !decoded.claims.jti.is_empty() && denylist.contains(&decoded.claims.jti) {
            return KyaVerdict::Revoked;
        }

        if let Some(required) = self.min_kyab_balance {
            let available = decoded
                .claims
                .kyab_balance
                .as_ref()
                .map(|balance| spendable_amount(balance, chrono::Utc::now()))
                .unwrap_or(0);
            if available < required {
                return KyaVerdict::InsufficientBalance { required };
            }
        }

        KyaVerdict::Verified(Box::new(VerifiedAgent {
            agent_id: decoded.claims.agent_id,
            vendor: decoded.claims.vendor,
            agent_class: decoded.claims.agent_class,
            kya_version: decoded.claims.kya_version,
            sub: decoded.claims.sub,
            kyab_balance: decoded.claims.kyab_balance,
        }))
    }

    /// Fetch or serve the issuer's JWKS. `None` means neither a fresh
    /// fetch nor a cached copy inside its stale-grace window.
    async fn jwks(&self, issuer: &KyaIssuer) -> Option<JwkSet> {
        if let Some(fresh) = read_fresh(&self.jwks_cache, &issuer.url) {
            return Some(fresh);
        }
        let url = issuer.jwks_url();
        match self.fetch_document::<JwkSet>(&url).await {
            Ok(jwks) => {
                store(&self.jwks_cache, &issuer.url, jwks.clone(), issuer);
                Some(jwks)
            }
            Err(reason) => {
                warn!(
                    issuer = %sbproxy_security::url_redact::redacted_url(&issuer.url),
                    reason,
                    "kya JWKS fetch failed; falling back to the cached copy"
                );
                read_stale(&self.jwks_cache, &issuer.url, issuer)
            }
        }
    }

    /// Fetch or serve the issuer's revocation list.
    ///
    /// A `404` is an empty denylist, not a failure: an issuer that has
    /// revoked nothing is not required to publish the document, and
    /// treating its absence as an outage would refuse every token from
    /// a healthy issuer.
    async fn denylist(&self, issuer: &KyaIssuer) -> Option<HashSet<String>> {
        if let Some(fresh) = read_fresh(&self.denylist_cache, &issuer.url) {
            return Some(fresh);
        }
        let url = issuer.denylist_url();
        match self.fetch_document::<Vec<String>>(&url).await {
            Ok(entries) => {
                let set: HashSet<String> = entries.into_iter().collect();
                store(&self.denylist_cache, &issuer.url, set.clone(), issuer);
                Some(set)
            }
            Err("not_found") => {
                let empty = HashSet::new();
                store(&self.denylist_cache, &issuer.url, empty.clone(), issuer);
                Some(empty)
            }
            Err(reason) => {
                warn!(
                    issuer = %sbproxy_security::url_redact::redacted_url(&issuer.url),
                    reason,
                    "kya denylist fetch failed; falling back to the cached copy"
                );
                read_stale(&self.denylist_cache, &issuer.url, issuer)
            }
        }
    }

    async fn fetch_document<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, &'static str> {
        // A JWKS or denylist fetch happens on the request path when the
        // cache misses, so it joins the ambient span rather than
        // appearing as a gap.
        let request =
            sbproxy_observe::telemetry::inject_reqwest_trace_context(self.client.get(url), None);
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() {
                "timeout"
            } else {
                "network"
            }
        })?;
        let status = response.status();
        if status == http::StatusCode::NOT_FOUND {
            return Err("not_found");
        }
        if !status.is_success() {
            return Err("http_error");
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_DOCUMENT_BYTES as u64)
        {
            return Err("too_large");
        }
        let body = response.bytes().await.map_err(|_| "network")?;
        if body.len() > MAX_DOCUMENT_BYTES {
            return Err("too_large");
        }
        serde_json::from_slice(&body).map_err(|_| "parse")
    }
}

/// Read a cached document that is still inside its freshness window.
fn read_fresh<T: Clone>(
    cache: &RwLock<HashMap<String, CachedDocument<T>>>,
    key: &str,
) -> Option<T> {
    let guard = cache.read();
    let entry = guard.get(key)?;
    (Instant::now() <= entry.fresh_until).then(|| entry.value.clone())
}

/// Read a cached document that is stale but still inside its
/// stale-grace window.
fn read_stale<T: Clone>(
    cache: &RwLock<HashMap<String, CachedDocument<T>>>,
    key: &str,
    issuer: &KyaIssuer,
) -> Option<T> {
    let guard = cache.read();
    let entry = guard.get(key)?;
    let usable_for = issuer.refresh_interval() + Duration::from_secs(issuer.stale_grace_secs);
    (Instant::now().duration_since(entry.fetched_at) <= usable_for).then(|| entry.value.clone())
}

fn store<T>(
    cache: &RwLock<HashMap<String, CachedDocument<T>>>,
    key: &str,
    value: T,
    issuer: &KyaIssuer,
) {
    let now = Instant::now();
    cache.write().insert(
        key.to_string(),
        CachedDocument {
            value,
            fetched_at: now,
            fresh_until: now + issuer.refresh_interval(),
        },
    );
}

/// Read the `iss` claim out of a token without verifying anything.
fn peek_issuer(token: &str) -> Option<String> {
    use base64::Engine as _;
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    // A third part has to exist: a two-part token is unsigned.
    parts.next()?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    if decoded.len() > MAX_DOCUMENT_BYTES {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Map a `jsonwebtoken` error onto a verdict.
///
/// Expiry is split out because it is the one refusal an agent can fix
/// by itself.
fn classify_jwt_error(error: &jsonwebtoken::errors::Error) -> KyaVerdict {
    use jsonwebtoken::errors::ErrorKind;
    match error.kind() {
        ErrorKind::ExpiredSignature => KyaVerdict::Expired,
        ErrorKind::InvalidAudience => KyaVerdict::Invalid {
            reason: "audience_mismatch",
        },
        ErrorKind::InvalidIssuer => KyaVerdict::Invalid {
            reason: "untrusted_issuer",
        },
        ErrorKind::InvalidSignature => KyaVerdict::Invalid {
            reason: "signature_invalid",
        },
        ErrorKind::ImmatureSignature => KyaVerdict::Invalid {
            reason: "not_yet_valid",
        },
        _ => KyaVerdict::Invalid {
            reason: "malformed",
        },
    }
}

/// How much of a balance is actually spendable right now.
///
/// A balance whose `expires_at` has passed is worth nothing: the
/// issuer said so, and admitting on it would be spending an allowance
/// the issuer has already withdrawn. An unparseable `expires_at` is
/// treated the same way rather than as an unlimited one.
fn spendable_amount(balance: &KyabBalance, now: chrono::DateTime<chrono::Utc>) -> u64 {
    match chrono::DateTime::parse_from_rfc3339(&balance.expires_at) {
        Ok(expires_at) if expires_at.with_timezone(&chrono::Utc) > now => balance.amount,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier(min_balance: Option<u64>) -> KyaVerifier {
        let mut config = serde_json::json!({
            "type": "kya",
            "issuers": [{"url": "https://api.skyfire.test"}],
        });
        if let Some(min) = min_balance {
            config["min_kyab_balance"] = serde_json::json!(min);
        }
        KyaVerifier::from_config(config).expect("verifier compiles")
    }

    fn balance(amount: u64, expires_at: &str) -> KyabBalance {
        KyabBalance {
            amount,
            currency: "USD".to_string(),
            expires_at: expires_at.to_string(),
        }
    }

    #[test]
    fn from_config_requires_at_least_one_issuer() {
        let error = KyaVerifier::from_config(serde_json::json!({
            "type": "kya",
            "issuers": [],
        }))
        .expect_err("an empty allowlist must not compile");
        assert!(error.to_string().contains("issuers"), "{error:#}");
    }

    #[test]
    fn from_config_refuses_a_plaintext_issuer() {
        let error = KyaVerifier::from_config(serde_json::json!({
            "type": "kya",
            "issuers": [{"url": "http://api.skyfire.test"}],
        }))
        .expect_err("a plaintext issuer must not compile");
        assert!(error.to_string().contains("https://"), "{error:#}");
    }

    #[test]
    fn from_config_refuses_an_unknown_key() {
        let error = KyaVerifier::from_config(serde_json::json!({
            "type": "kya",
            "issuers": [{"url": "https://api.skyfire.test"}],
            "fail_opne": true,
        }))
        .expect_err("a misspelled fail-open key must not compile");
        assert!(error.to_string().contains("fail_opne"), "{error:#}");
    }

    #[test]
    fn refresh_interval_is_clamped_at_both_ends() {
        let fast = KyaIssuer {
            url: "https://issuer.test".to_string(),
            jwks_refresh_interval_secs: 1,
            stale_grace_secs: 0,
        };
        assert_eq!(
            fast.refresh_interval(),
            Duration::from_secs(MIN_REFRESH_SECS)
        );
        let slow = KyaIssuer {
            url: "https://issuer.test".to_string(),
            jwks_refresh_interval_secs: 10 * MAX_REFRESH_SECS,
            stale_grace_secs: 0,
        };
        assert_eq!(
            slow.refresh_interval(),
            Duration::from_secs(MAX_REFRESH_SECS)
        );
    }

    #[test]
    fn well_known_urls_are_composed_without_a_double_slash() {
        let issuer = KyaIssuer {
            url: "https://issuer.test/".to_string(),
            jwks_refresh_interval_secs: DEFAULT_REFRESH_SECS,
            stale_grace_secs: DEFAULT_STALE_GRACE_SECS,
        };
        assert_eq!(
            issuer.jwks_url(),
            "https://issuer.test/.well-known/jwks.json"
        );
        assert_eq!(
            issuer.denylist_url(),
            "https://issuer.test/.well-known/kya-denylist.json"
        );
    }

    #[tokio::test]
    async fn an_absent_header_is_missing_rather_than_invalid() {
        let verdict = verifier(None)
            .verify(&http::HeaderMap::new(), "gateway.test")
            .await;
        assert_eq!(verdict, KyaVerdict::Missing);
        assert_eq!(verdict.metric_label(), "missing");
    }

    #[tokio::test]
    async fn a_blank_header_is_missing_rather_than_malformed() {
        let mut headers = http::HeaderMap::new();
        headers.insert(KYA_HEADER, http::HeaderValue::from_static("   "));
        assert_eq!(
            verifier(None).verify(&headers, "gateway.test").await,
            KyaVerdict::Missing
        );
    }

    #[tokio::test]
    async fn a_token_from_an_unlisted_issuer_is_refused_without_a_fetch() {
        // The issuer here resolves nowhere, so if the allowlist check
        // did not run first this test would hang on a DNS lookup
        // rather than return.
        let claims = serde_json::json!({
            "iss": "https://evil.invalid",
            "exp": 9_999_999_999_u64,
            "aud": "gateway.test",
        });
        let token = unsigned_token(&claims);
        let verdict = verifier(None)
            .verify_token(Some(&token), "gateway.test")
            .await;
        assert_eq!(
            verdict,
            KyaVerdict::Invalid {
                reason: "untrusted_issuer"
            }
        );
    }

    #[tokio::test]
    async fn a_token_signed_with_an_unsupported_alg_is_refused() {
        // `alg: HS256` with a header the verifier can decode: the
        // algorithm pin has to refuse it before any key lookup.
        let header = serde_json::json!({"alg": "HS256", "kid": "k1"});
        let claims = serde_json::json!({"iss": "https://api.skyfire.test"});
        let token = format!(
            "{}.{}.{}",
            b64(&header),
            b64(&claims),
            "c2lnbmF0dXJl" // "signature"
        );
        assert_eq!(
            verifier(None)
                .verify_token(Some(&token), "gateway.test")
                .await,
            KyaVerdict::Invalid {
                reason: "unsupported_alg"
            }
        );
    }

    #[tokio::test]
    async fn a_token_with_no_kid_is_refused() {
        let header = serde_json::json!({"alg": "ES256"});
        let claims = serde_json::json!({"iss": "https://api.skyfire.test"});
        let token = format!("{}.{}.{}", b64(&header), b64(&claims), "c2ln");
        assert_eq!(
            verifier(None)
                .verify_token(Some(&token), "gateway.test")
                .await,
            KyaVerdict::Invalid {
                reason: "malformed"
            }
        );
    }

    #[test]
    fn an_expired_balance_is_worth_nothing() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
            .expect("fixed now parses")
            .with_timezone(&chrono::Utc);
        assert_eq!(
            spendable_amount(&balance(5_000, "2026-08-27T13:00:00Z"), now),
            5_000
        );
        assert_eq!(
            spendable_amount(&balance(5_000, "2026-08-27T11:00:00Z"), now),
            0,
            "a balance the issuer already withdrew must not be spendable"
        );
        assert_eq!(
            spendable_amount(&balance(5_000, "not-a-timestamp"), now),
            0,
            "an unparseable expiry must not read as unlimited"
        );
    }

    #[test]
    fn verdict_labels_are_the_closed_scripting_set() {
        assert_eq!(KyaVerdict::Missing.metric_label(), "missing");
        assert_eq!(KyaVerdict::Expired.metric_label(), "expired");
        assert_eq!(KyaVerdict::Revoked.metric_label(), "revoked");
        assert_eq!(
            KyaVerdict::DirectoryUnavailable.metric_label(),
            "directory_unavailable"
        );
        assert_eq!(
            KyaVerdict::InsufficientBalance { required: 1 }.metric_label(),
            "insufficient_balance"
        );
        assert_eq!(
            KyaVerdict::Invalid {
                reason: "signature_invalid"
            }
            .metric_label(),
            "invalid",
            "the fine-grained reason belongs in the log, not the label"
        );
        assert_eq!(
            KyaVerdict::Invalid {
                reason: "signature_invalid"
            }
            .reason(),
            "signature_invalid"
        );
    }

    #[test]
    fn peek_issuer_refuses_an_unsigned_two_part_token() {
        let claims = serde_json::json!({"iss": "https://api.skyfire.test"});
        let two_part = format!(
            "{}.{}",
            b64(&serde_json::json!({"alg": "ES256"})),
            b64(&claims)
        );
        assert_eq!(peek_issuer(&two_part), None);
    }

    #[test]
    fn peek_issuer_reads_the_claim_without_verifying() {
        let claims = serde_json::json!({"iss": "https://api.skyfire.test"});
        let token = format!(
            "{}.{}.{}",
            b64(&serde_json::json!({"alg": "ES256"})),
            b64(&claims),
            "c2ln"
        );
        assert_eq!(
            peek_issuer(&token).as_deref(),
            Some("https://api.skyfire.test")
        );
    }

    fn b64(value: &serde_json::Value) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(value).expect("value serializes"))
    }

    fn unsigned_token(claims: &serde_json::Value) -> String {
        format!(
            "{}.{}.{}",
            b64(&serde_json::json!({"alg": "ES256", "kid": "k1"})),
            b64(claims),
            "c2ln"
        )
    }
}

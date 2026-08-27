//! The signed agent catalog feed, and the two-tier Ed25519 verification
//! that decides whether a fetched document is allowed to become a catalog.
//!
//! # Two tiers, and why
//!
//! A small set of bootstrap public keys, supplied by the operator in
//! configuration, signs a *key directory*. The key directory names the
//! per-period keys that sign individual feed bodies. A feed signing key that
//! leaks therefore buys an attacker one signing period and no authority over
//! the directory, and rotating it is a directory republish rather than a
//! fleet-wide config change.
//!
//! The bootstrap set has no default. The enterprise implementation this
//! replaces shipped a single placeholder entry of thirty-two zero bytes so
//! the verification path would compile end to end; a build that ships a
//! known public key is a build where anyone holding the matching private key
//! signs directories. Here, an empty bootstrap set refuses verification
//! outright, which is the fail-closed direction.
//!
//! # What is signed
//!
//! Both documents carry a detached signature over the RFC 8785 canonical
//! form of their own body with the `signature` member removed. Canonical
//! JSON is what makes that reproducible: the verifier does not have to
//! preserve the publisher's byte layout, key order, or whitespace, only its
//! values. `serde_json_canonicalizer` is the workspace's existing JCS
//! implementation, already used for the x402 payment envelope and the
//! semantic-cache key, rather than a fourth hand-rolled canonicalizer.
//!
//! # What verification does not do
//!
//! It does not fetch. There is no HTTP client in this crate and no URL in
//! its configuration: the operator points sbproxy at a feed file and a key
//! directory file on disk, and syncs those files by whatever means already
//! moves configuration onto the host. An outbound poller reachable from
//! configuration is a fetch primitive, and the catalog is not worth adding
//! one for when the alternative is two files.

use std::collections::BTreeMap;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::error::{RegistryError, Result};

/// Newest wire format this build understands. A document declaring a higher
/// version is refused rather than parsed leniently: a newer publisher may
/// have added a field whose absence changes what the document means.
const MAX_SUPPORTED_FORMAT_VERSION: u32 = 1;

/// Largest document this crate will parse, in bytes.
///
/// Both documents are operator-supplied files, so this is a guard against a
/// mistake rather than an attacker, but a parse with no bound is still an
/// unbounded allocation and there is no reason for a catalog to be larger
/// than this.
const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;

/// Largest number of entries a feed may carry.
const MAX_FEED_ENTRIES: usize = 10_000;

/// Agent ids the resolver reserves for its own sentinels. A feed that claims
/// one of them is refused, because a catalog entry named `human` would
/// shadow the answer "this was not an agent".
const RESERVED_AGENT_IDS: [&str; 3] = ["human", "unknown", "anonymous"];

/// One catalog entry: an agent the operator's policies can name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEntry {
    /// Stable agent identifier, kebab-case.
    pub agent_id: String,
    /// Display name of the operator behind the agent.
    pub vendor: String,
    /// Purpose bucket. Free-form on the wire so a future taxonomy addition
    /// is not a breaking change for an older reader.
    pub purpose: String,
    /// User-Agent fragments this agent is expected to send.
    #[serde(default)]
    pub expected_user_agents: Vec<String>,
    /// Reverse-DNS suffixes a forward-confirmed lookup should land in.
    #[serde(default)]
    pub expected_reverse_dns_suffixes: Vec<String>,
    /// Web Bot Auth key thumbprints, `<alg>:<thumbprint>`.
    #[serde(default)]
    pub expected_keyids: Vec<String>,
    /// Composite reputation score, `0..=100`. A policy input, never a
    /// metric label.
    pub reputation_score: u8,
    /// Closed-ish set of advisory flags (`throttled`, `deprecated`,
    /// `incident`, `unverified`).
    #[serde(default)]
    pub flags: Vec<String>,
}

/// A detached signature: which key signed, and the signature itself.
///
/// Crate-private, and the two `signature` fields below are too. A verified
/// [`AgentFeed`] is the only kind this crate hands out, so nothing outside
/// it has a reason to read a signature, and nothing outside it should be
/// able to assemble a feed value that never went through
/// [`verify_feed`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FeedSignature {
    /// Identifier of the signing key.
    pub(crate) kid: String,
    /// Base64 (standard alphabet) of the raw 64-byte Ed25519 signature.
    pub(crate) sig: String,
}

/// The signed catalog document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFeed {
    /// Wire format version.
    pub format_version: u32,
    /// When the publisher built this feed.
    pub generated_at: DateTime<Utc>,
    /// When subscribers should stop trusting it.
    pub expires_at: DateTime<Utc>,
    /// The catalog itself.
    pub entries: Vec<FeedEntry>,
    /// Detached signature over the canonical body with this member removed.
    pub(crate) signature: FeedSignature,
}

/// One per-period feed signing key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyEntry {
    /// Identifier a feed's `signature.kid` references.
    pub(crate) kid: String,
    /// Algorithm tag. Only `ed25519` is accepted.
    pub(crate) alg: String,
    /// Base64 of the raw 32-byte Ed25519 public key.
    pub(crate) public_key: String,
}

/// A key the publisher has permanently withdrawn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokedEntry {
    /// The withdrawn key's identifier.
    pub(crate) kid: String,
    /// When it was withdrawn.
    pub(crate) revoked_at: DateTime<Utc>,
    /// Why, for the operator reading an audit trail.
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

/// The signed directory of per-period feed signing keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyDirectory {
    /// Wire format version.
    pub(crate) format_version: u32,
    /// When the publisher built this directory.
    pub(crate) generated_at: DateTime<Utc>,
    /// The key the publisher signs new feeds with.
    pub(crate) active: KeyEntry,
    /// Recently rotated keys still acceptable during the overlap window.
    #[serde(default)]
    pub(crate) grace: Vec<KeyEntry>,
    /// Keys no feed may be signed with, whatever else says otherwise.
    #[serde(default)]
    pub(crate) revoked: Vec<RevokedEntry>,
    /// Detached signature over the canonical body with this member removed,
    /// verified against the operator's bootstrap keys.
    pub(crate) signature: FeedSignature,
}

impl KeyDirectory {
    /// Resolve `kid` to a usable verifying key.
    ///
    /// Revocation wins over everything. A publisher that rotated a key into
    /// `grace` and then discovered it was compromised republishes the
    /// directory with the same kid in `revoked`, and a subscriber that
    /// checked `grace` first would keep accepting the compromised key for
    /// the whole overlap window.
    fn resolve(&self, kid: &str) -> Result<VerifyingKey> {
        if self.revoked.iter().any(|entry| entry.kid == kid) {
            return Err(RegistryError::UnknownKey(kid.to_string()));
        }
        let entry = std::iter::once(&self.active)
            .chain(self.grace.iter())
            .find(|entry| entry.kid == kid)
            .ok_or_else(|| RegistryError::UnknownKey(kid.to_string()))?;
        decode_verifying_key(entry)
    }
}

/// The operator-supplied bootstrap keys that vouch for a key directory.
#[derive(Debug, Clone, Default)]
pub struct BootstrapKeys(BTreeMap<String, VerifyingKey>);

impl BootstrapKeys {
    /// Build a bootstrap set from `(kid, base64 public key)` pairs.
    ///
    /// An empty set is allowed to exist so a config with no
    /// `bootstrap_keys:` still builds a value; it is
    /// [`verify_key_directory`] that refuses to verify against one, so the
    /// refusal names the operation an operator was trying to do rather than
    /// failing at config load in a subsystem they may not have configured.
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: AsRef<str>,
    {
        let mut map = BTreeMap::new();
        for (kid, encoded) in pairs {
            let kid = kid.into();
            let key = decode_public_key(&kid, encoded.as_ref())?;
            map.insert(kid, key);
        }
        Ok(Self(map))
    }

    /// Whether the set has no keys, in which case nothing can verify.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many bootstrap keys are configured.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Decode a base64 Ed25519 public key.
fn decode_public_key(kid: &str, encoded: &str) -> Result<VerifyingKey> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|error| RegistryError::Invalid {
            field: "public_key",
            detail: format!("key {kid} is not base64: {error}"),
        })?;
    let bytes: [u8; PUBLIC_KEY_LENGTH] = raw.try_into().map_err(|_| RegistryError::Invalid {
        field: "public_key",
        detail: format!("key {kid} is not {PUBLIC_KEY_LENGTH} bytes"),
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|error| RegistryError::Invalid {
        field: "public_key",
        detail: format!("key {kid} is not a valid Ed25519 point: {error}"),
    })
}

/// Decode a directory entry into a verifying key, refusing any algorithm
/// other than Ed25519 rather than ignoring the tag.
fn decode_verifying_key(entry: &KeyEntry) -> Result<VerifyingKey> {
    if entry.alg != "ed25519" {
        return Err(RegistryError::Invalid {
            field: "alg",
            detail: format!(
                "key {} declares unsupported algorithm {}",
                entry.kid, entry.alg
            ),
        });
    }
    decode_public_key(&entry.kid, &entry.public_key)
}

/// Canonicalize a document body with its `signature` member removed, which
/// is exactly the byte string a publisher signed.
fn signing_payload(document: &serde_json::Value) -> Result<Vec<u8>> {
    let mut body = document.clone();
    let object = body.as_object_mut().ok_or_else(|| RegistryError::Invalid {
        field: "document",
        detail: "signed documents must be JSON objects".into(),
    })?;
    object.remove("signature");
    serde_json_canonicalizer::to_vec(&body).map_err(|error| RegistryError::Invalid {
        field: "document",
        detail: format!("could not canonicalize: {error}"),
    })
}

/// Read the `signature` member without deserializing the whole document,
/// so a body that fails signature verification is never handed to a typed
/// parser.
fn read_signature(document: &serde_json::Value) -> Result<FeedSignature> {
    let raw = document
        .get("signature")
        .ok_or_else(|| RegistryError::Invalid {
            field: "signature",
            detail: "document carries no signature".into(),
        })?;
    serde_json::from_value(raw.clone()).map_err(|error| RegistryError::Invalid {
        field: "signature",
        detail: format!("malformed signature member: {error}"),
    })
}

/// Verify a detached signature over a document body.
fn verify_detached(
    document: &serde_json::Value,
    signature: &FeedSignature,
    key: &VerifyingKey,
) -> Result<()> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(signature.sig.trim())
        .map_err(|error| RegistryError::Signature(format!("signature is not base64: {error}")))?;
    let bytes: [u8; SIGNATURE_LENGTH] = raw.try_into().map_err(|_| {
        RegistryError::Signature(format!("signature is not {SIGNATURE_LENGTH} bytes"))
    })?;
    let payload = signing_payload(document)?;
    key.verify(&payload, &Signature::from_bytes(&bytes))
        .map_err(|_| {
            RegistryError::Signature(format!("key {} did not sign this body", signature.kid))
        })
}

/// Parse a document, refusing anything past the size cap before the parser
/// sees it.
fn parse_document(bytes: &[u8]) -> Result<serde_json::Value> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(RegistryError::Invalid {
            field: "document",
            detail: format!(
                "{} bytes is past the {MAX_DOCUMENT_BYTES} byte cap",
                bytes.len()
            ),
        });
    }
    serde_json::from_slice(bytes).map_err(|error| RegistryError::Invalid {
        field: "document",
        detail: format!("not JSON: {error}"),
    })
}

/// Verify a key directory against the operator's bootstrap keys.
pub(crate) fn verify_key_directory(
    bytes: &[u8],
    bootstrap: &BootstrapKeys,
) -> Result<KeyDirectory> {
    if bootstrap.is_empty() {
        return Err(RegistryError::UnknownKey(
            "no bootstrap keys are configured, so no key directory can be trusted".into(),
        ));
    }
    let document = parse_document(bytes)?;
    let signature = read_signature(&document)?;
    let key = bootstrap
        .0
        .get(&signature.kid)
        .ok_or_else(|| RegistryError::UnknownKey(signature.kid.clone()))?;
    verify_detached(&document, &signature, key)?;

    let directory: KeyDirectory =
        serde_json::from_value(document).map_err(|error| RegistryError::Invalid {
            field: "key_directory",
            detail: error.to_string(),
        })?;
    if directory.format_version > MAX_SUPPORTED_FORMAT_VERSION {
        return Err(RegistryError::UnsupportedFormatVersion {
            found: directory.format_version,
            supported: MAX_SUPPORTED_FORMAT_VERSION,
        });
    }
    Ok(directory)
}

/// Verify a feed against a directory that has itself already been verified.
///
/// `stale_grace` extends `expires_at`: an operator who would rather serve a
/// day-old catalog than none sets it, and one who would rather fail closed
/// leaves it at zero. Either way the feed's own expiry is what the grace
/// extends, so a publisher's expiry decision is never silently ignored.
pub(crate) fn verify_feed(
    bytes: &[u8],
    directory: &KeyDirectory,
    now: DateTime<Utc>,
    stale_grace: Duration,
) -> Result<AgentFeed> {
    let document = parse_document(bytes)?;
    let signature = read_signature(&document)?;
    let key = directory.resolve(&signature.kid)?;
    verify_detached(&document, &signature, &key)?;

    let feed: AgentFeed =
        serde_json::from_value(document).map_err(|error| RegistryError::Invalid {
            field: "feed",
            detail: error.to_string(),
        })?;
    if feed.format_version > MAX_SUPPORTED_FORMAT_VERSION {
        return Err(RegistryError::UnsupportedFormatVersion {
            found: feed.format_version,
            supported: MAX_SUPPORTED_FORMAT_VERSION,
        });
    }
    if feed.entries.len() > MAX_FEED_ENTRIES {
        return Err(RegistryError::Invalid {
            field: "entries",
            detail: format!(
                "{} entries is past the {MAX_FEED_ENTRIES} entry cap",
                feed.entries.len()
            ),
        });
    }
    if now >= feed.expires_at + stale_grace {
        return Err(RegistryError::FeedExpired {
            expired_at: feed.expires_at.to_rfc3339(),
        });
    }
    for entry in &feed.entries {
        if RESERVED_AGENT_IDS.contains(&entry.agent_id.as_str()) {
            return Err(RegistryError::Invalid {
                field: "agent_id",
                detail: format!("{} is reserved by the resolver", entry.agent_id),
            });
        }
        if entry.reputation_score > 100 {
            return Err(RegistryError::Invalid {
                field: "reputation_score",
                detail: format!("{} is outside 0..=100", entry.reputation_score),
            });
        }
    }
    Ok(feed)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Publisher-side helpers. Signing lives only in tests because sbproxy
    //! is a subscriber: nothing in the shipped binary holds a feed private
    //! key, and a signer in production code would be a key this process has
    //! no reason to be able to use.

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub(crate) fn sign_document(
        mut document: serde_json::Value,
        kid: &str,
        key: &SigningKey,
    ) -> Vec<u8> {
        if let Some(object) = document.as_object_mut() {
            object.remove("signature");
        }
        let payload = serde_json_canonicalizer::to_vec(&document).expect("canonicalize");
        let signature = key.sign(&payload);
        if let Some(object) = document.as_object_mut() {
            object.insert(
                "signature".into(),
                serde_json::json!({
                    "kid": kid,
                    "sig": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
                }),
            );
        }
        serde_json::to_vec(&document).expect("serialize")
    }

    pub(crate) fn public_b64(key: &SigningKey) -> String {
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{public_b64, sign_document};
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("fixed instant")
    }

    fn directory_body(active: &SigningKey, active_kid: &str) -> serde_json::Value {
        serde_json::json!({
            "format_version": 1,
            "generated_at": now().to_rfc3339(),
            "active": {"kid": active_kid, "alg": "ed25519", "public_key": public_b64(active)},
            "grace": [],
            "revoked": [],
        })
    }

    fn feed_body(kid: &str) -> serde_json::Value {
        serde_json::json!({
            "format_version": 1,
            "generated_at": now().to_rfc3339(),
            "expires_at": (now() + Duration::hours(24)).to_rfc3339(),
            "entries": [{
                "agent_id": "acme-crawler",
                "vendor": "Acme",
                "purpose": "search",
                "expected_user_agents": ["AcmeBot/1.0"],
                "reputation_score": 80,
            }],
            "signature": {"kid": kid, "sig": ""},
        })
    }

    fn verified_directory(bootstrap_key: &SigningKey, feed_key: &SigningKey) -> KeyDirectory {
        let bootstrap = BootstrapKeys::from_pairs([("boot-1", public_b64(bootstrap_key))])
            .expect("bootstrap set");
        let bytes = sign_document(directory_body(feed_key, "feed-1"), "boot-1", bootstrap_key);
        verify_key_directory(&bytes, &bootstrap).expect("directory verifies")
    }

    #[test]
    fn a_correctly_signed_feed_verifies_end_to_end() {
        let bootstrap_key = SigningKey::generate(&mut OsRng);
        let feed_key = SigningKey::generate(&mut OsRng);
        let directory = verified_directory(&bootstrap_key, &feed_key);

        let bytes = sign_document(feed_body("feed-1"), "feed-1", &feed_key);
        let feed = verify_feed(&bytes, &directory, now(), Duration::zero()).expect("feed verifies");
        assert_eq!(feed.entries.len(), 1);
        assert_eq!(feed.entries[0].agent_id, "acme-crawler");
    }

    /// The whole point of the two tiers. A key that only the directory
    /// vouches for cannot vouch for a directory, and a body signed by
    /// anything the directory does not name is refused rather than parsed.
    #[test]
    fn a_feed_signed_by_an_unlisted_key_is_refused() {
        let bootstrap_key = SigningKey::generate(&mut OsRng);
        let feed_key = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let directory = verified_directory(&bootstrap_key, &feed_key);

        // Right kid, wrong private key: the signature does not verify.
        let forged = sign_document(feed_body("feed-1"), "feed-1", &attacker);
        assert!(matches!(
            verify_feed(&forged, &directory, now(), Duration::zero()),
            Err(RegistryError::Signature(_))
        ));

        // Honest signature under a kid the directory never listed.
        let unlisted = sign_document(feed_body("attacker-1"), "attacker-1", &attacker);
        assert!(matches!(
            verify_feed(&unlisted, &directory, now(), Duration::zero()),
            Err(RegistryError::UnknownKey(_))
        ));
    }

    /// A body edit after signing has to fail, or the signature is
    /// decoration. Canonical JSON is what makes this detectable without the
    /// verifier preserving the publisher's byte layout.
    #[test]
    fn an_edited_body_no_longer_verifies() {
        let bootstrap_key = SigningKey::generate(&mut OsRng);
        let feed_key = SigningKey::generate(&mut OsRng);
        let directory = verified_directory(&bootstrap_key, &feed_key);

        let bytes = sign_document(feed_body("feed-1"), "feed-1", &feed_key);
        let mut document: serde_json::Value = serde_json::from_slice(&bytes).expect("parse");
        document["entries"][0]["reputation_score"] = serde_json::json!(5);
        let tampered = serde_json::to_vec(&document).expect("serialize");

        assert!(matches!(
            verify_feed(&tampered, &directory, now(), Duration::zero()),
            Err(RegistryError::Signature(_))
        ));

        // Reordering members and reindenting changes the bytes but not the
        // canonical form, so it must still verify.
        let reserialized = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&bytes).expect("parse"),
        )
        .expect("serialize");
        assert!(verify_feed(&reserialized, &directory, now(), Duration::zero()).is_ok());
    }

    /// Revocation has to beat the grace list, or a publisher who discovers a
    /// rotated key was compromised cannot withdraw it inside the overlap
    /// window.
    #[test]
    fn a_revoked_kid_is_refused_even_while_it_is_also_in_grace() {
        let bootstrap_key = SigningKey::generate(&mut OsRng);
        let active = SigningKey::generate(&mut OsRng);
        let retired = SigningKey::generate(&mut OsRng);
        let bootstrap =
            BootstrapKeys::from_pairs([("boot-1", public_b64(&bootstrap_key))]).expect("bootstrap");

        let body = serde_json::json!({
            "format_version": 1,
            "generated_at": now().to_rfc3339(),
            "active": {"kid": "feed-2", "alg": "ed25519", "public_key": public_b64(&active)},
            "grace": [{"kid": "feed-1", "alg": "ed25519", "public_key": public_b64(&retired)}],
            "revoked": [{"kid": "feed-1", "revoked_at": now().to_rfc3339(), "reason": "compromised"}],
        });
        let directory =
            verify_key_directory(&sign_document(body, "boot-1", &bootstrap_key), &bootstrap)
                .expect("directory verifies");

        let feed = sign_document(feed_body("feed-1"), "feed-1", &retired);
        assert!(matches!(
            verify_feed(&feed, &directory, now(), Duration::zero()),
            Err(RegistryError::UnknownKey(_))
        ));
    }

    /// An empty bootstrap set is the state a build ships in. Verification
    /// has to refuse there rather than fall back to a baked-in key.
    #[test]
    fn an_empty_bootstrap_set_trusts_nothing() {
        let bootstrap_key = SigningKey::generate(&mut OsRng);
        let feed_key = SigningKey::generate(&mut OsRng);
        let bytes = sign_document(
            directory_body(&feed_key, "feed-1"),
            "boot-1",
            &bootstrap_key,
        );
        assert!(matches!(
            verify_key_directory(&bytes, &BootstrapKeys::default()),
            Err(RegistryError::UnknownKey(_))
        ));
    }

    #[test]
    fn an_expired_feed_is_refused_unless_the_operator_allowed_the_staleness() {
        let bootstrap_key = SigningKey::generate(&mut OsRng);
        let feed_key = SigningKey::generate(&mut OsRng);
        let directory = verified_directory(&bootstrap_key, &feed_key);
        let bytes = sign_document(feed_body("feed-1"), "feed-1", &feed_key);

        let past_expiry = now() + Duration::hours(25);
        assert!(matches!(
            verify_feed(&bytes, &directory, past_expiry, Duration::zero()),
            Err(RegistryError::FeedExpired { .. })
        ));
        assert!(verify_feed(&bytes, &directory, past_expiry, Duration::hours(6)).is_ok());
    }

    #[test]
    fn a_reserved_agent_id_is_refused() {
        let bootstrap_key = SigningKey::generate(&mut OsRng);
        let feed_key = SigningKey::generate(&mut OsRng);
        let directory = verified_directory(&bootstrap_key, &feed_key);

        let mut body = feed_body("feed-1");
        body["entries"][0]["agent_id"] = serde_json::json!("human");
        let bytes = sign_document(body, "feed-1", &feed_key);
        assert!(matches!(
            verify_feed(&bytes, &directory, now(), Duration::zero()),
            Err(RegistryError::Invalid {
                field: "agent_id",
                ..
            })
        ));
    }

    #[test]
    fn a_non_ed25519_key_entry_is_refused_rather_than_ignored() {
        let bootstrap_key = SigningKey::generate(&mut OsRng);
        let feed_key = SigningKey::generate(&mut OsRng);
        let bootstrap =
            BootstrapKeys::from_pairs([("boot-1", public_b64(&bootstrap_key))]).expect("bootstrap");
        let mut body = directory_body(&feed_key, "feed-1");
        body["active"]["alg"] = serde_json::json!("rsa");
        let directory =
            verify_key_directory(&sign_document(body, "boot-1", &bootstrap_key), &bootstrap)
                .expect("directory itself still verifies");

        let feed = sign_document(feed_body("feed-1"), "feed-1", &feed_key);
        assert!(matches!(
            verify_feed(&feed, &directory, now(), Duration::zero()),
            Err(RegistryError::Invalid { field: "alg", .. })
        ));
    }
}

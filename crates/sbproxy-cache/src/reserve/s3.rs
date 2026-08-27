//! S3 [`CacheReserveBackend`] with AWS KMS envelope encryption.
//!
//! A cold, cross-region-replicable cache tier: bodies are sealed with
//! AES-256-GCM under a per-object data key, and the data key itself is
//! wrapped by a KMS master key (`KMS:GenerateDataKey` on write,
//! `KMS:Decrypt` on read). This "envelope encryption" pattern keeps
//! KMS request volume bounded to one call per object instead of one
//! per byte, and lets the master key rotate without rewriting object
//! bodies. Deployments that prefer bucket-default SSE-KMS instead of
//! local envelope encryption can set
//! [`S3ReserveConfig::sse_kms_bucket_default`]; in that mode the body
//! uploads in plaintext and S3 encrypts at rest, and `put`/`get` never
//! call KMS directly.
//!
//! Cross-region replication is configured at the bucket level by S3
//! itself (a replication rule plus an IAM role); this backend only
//! writes to the source bucket. [`S3ReserveConfig::replication_target_bucket`]
//! is a diagnostics-only hint, not something this code acts on.
//!
//! [`ReserveMetadata`] is stored whole: a `put` JSON-serializes it and
//! base64-encodes the result into one S3 user-metadata field
//! (`sbproxy-meta`), the same "serialize the struct, don't explode it
//! into named fields" approach [`super::redis::RedisReserve`] and
//! [`super::filesystem::FsReserve`] already take. That is a deliberate
//! difference from the sibling implementation this backend was ported
//! from, which wrote each `ReserveMetadata` field as its own S3
//! metadata key: exploded fields drift out of sync the next time
//! `ReserveMetadata` grows a field (it already has once, gaining
//! `headers`, since that backend was last synced), where a whole-struct
//! blob round-trips automatically. The AWS SDK client is built lazily
//! on first use through a `tokio::sync::OnceCell`, so concurrent first
//! use performs one initialization while constructing an [`S3Reserve`]
//! from YAML still needs no async context.
//!
//! S3 combines the size of every `x-amz-meta-*` key and value into one
//! 2 KiB budget per object. The `sbproxy-meta` blob competes with the
//! encryption housekeeping fields (`sbproxy-encryption`,
//! `sbproxy-wrapped-key`, `sbproxy-nonce`) for that budget; a response
//! with an unusually large header set can exceed it, in which case
//! `put` surfaces the S3-reported error like any other write failure.

use std::collections::HashMap;
use std::time::SystemTime;

use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{Delete, ObjectIdentifier, ServerSideEncryption};
use base64::Engine as _;
use bytes::Bytes;
use sbproxy_security::crypto::{
    aes256gcm_decrypt, aes256gcm_encrypt, random_aes_gcm_nonce, AES256_KEY_LEN, AES_GCM_NONCE_LEN,
};
use tokio::sync::OnceCell;
use tracing::{debug, instrument, warn};
use zeroize::Zeroizing;

use super::{CacheReserveBackend, ReserveMetadata};

/// Whole-`ReserveMetadata` blob: base64(json(metadata)).
const META_META: &str = "sbproxy-meta";
/// Versioned envelope mode or `"sse-kms"`.
const META_ENCRYPTION: &str = "sbproxy-encryption";
/// base64(KMS-wrapped data key). Present only in envelope mode.
const META_WRAPPED_KEY: &str = "sbproxy-wrapped-key";
/// base64(AES-GCM nonce). Present only in envelope mode.
const META_NONCE: &str = "sbproxy-nonce";

/// AES-GCM appends one 128-bit authentication tag to the stored
/// ciphertext. The configured object limit applies to plaintext, so
/// envelope-mode reads allow exactly this much storage overhead.
const AES_GCM_TAG_LEN: u64 = 16;

/// Legacy envelopes used a process-constant AAD and are not safe to
/// read as key-bound objects.
const ENCRYPTION_ENVELOPE_V1: &str = "envelope-aes256gcm";
/// Current envelope format. Its AAD binds storage and cache identity.
const ENCRYPTION_ENVELOPE_V2: &str = "envelope-aes256gcm-v2";
/// Domain separator and wire-version marker for the canonical v2 AAD.
const AAD_V2_DOMAIN: &[u8] = b"sbproxy-cache-reserve-s3-aad-v2";

/// Soft warning threshold for [`S3Reserve::evict_expired`]. Past this
/// many listed objects, a HEAD-per-object sweep is expensive enough
/// that S3 lifecycle rules are the better tool.
const EVICT_OBJECT_WARN_THRESHOLD: u64 = 100_000;

/// Configuration for [`S3Reserve`].
#[derive(Debug, Clone)]
pub struct S3ReserveConfig {
    /// Source S3 bucket.
    pub bucket: String,
    /// AWS region the bucket lives in.
    pub region: String,
    /// KMS key ID, ARN, or alias. Used to wrap/unwrap the per-object
    /// data key in envelope mode, and as `ssekms_key_id` in
    /// bucket-default mode.
    pub kms_key_id: String,
    /// Optional key prefix (e.g. `"reserve/"`). A trailing `/` is
    /// preserved; none is inserted if absent.
    pub prefix: Option<String>,
    /// Optional replication target bucket name. Diagnostics only:
    /// cross-region replication is configured at the bucket level,
    /// outside this backend.
    pub replication_target_bucket: Option<String>,
    /// When `true`, upload plaintext and rely on S3 SSE-KMS
    /// bucket-default encryption instead of local envelope
    /// encryption. `put`/`get` never call `KMS:GenerateDataKey` or
    /// `KMS:Decrypt` in this mode.
    pub sse_kms_bucket_default: bool,
    /// Maximum allowed object size in bytes.
    pub max_size_bytes: u64,
}

/// S3-backed reserve with AWS KMS envelope encryption.
///
/// The AWS clients are built lazily on first `put`/`get`/`delete`/
/// `evict_expired` call rather than in [`S3Reserve::new`], so
/// constructing one from a config block does not require an async
/// context. Once built, the clients are cached and reused: they are
/// cheaply cloneable (reference-counted internally by the SDK).
pub struct S3Reserve {
    config: S3ReserveConfig,
    clients: OnceCell<(aws_sdk_s3::Client, aws_sdk_kms::Client)>,
}

impl std::fmt::Debug for S3Reserve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Reserve")
            .field("bucket", &self.config.bucket)
            .field("region", &self.config.region)
            .field("kms_key_id", &self.config.kms_key_id)
            .field("prefix", &self.config.prefix)
            .field(
                "replication_target_bucket",
                &self.config.replication_target_bucket,
            )
            .field(
                "sse_kms_bucket_default",
                &self.config.sse_kms_bucket_default,
            )
            .finish()
    }
}

impl S3Reserve {
    /// Validate `config` and build an `S3Reserve`.
    ///
    /// Does not touch the network: credential resolution and client
    /// construction are deferred to the first async call. Only the
    /// three fields a misconfigured YAML block is most likely to leave
    /// empty are checked here, so a typo shows up at config-compile
    /// time rather than on the first request that needs the reserve.
    pub fn new(config: S3ReserveConfig) -> anyhow::Result<Self> {
        if config.bucket.is_empty() {
            return Err(anyhow::anyhow!(
                "s3 cache reserve: bucket must not be empty"
            ));
        }
        if config.region.is_empty() {
            return Err(anyhow::anyhow!(
                "s3 cache reserve: region must not be empty"
            ));
        }
        if config.kms_key_id.is_empty() {
            return Err(anyhow::anyhow!(
                "s3 cache reserve: kms_key_id must not be empty"
            ));
        }
        Ok(Self {
            config,
            clients: OnceCell::new(),
        })
    }

    /// Build directly from pre-constructed AWS clients. Used by tests
    /// to inject a mocked HTTP layer.
    pub fn with_clients(
        config: S3ReserveConfig,
        s3: aws_sdk_s3::Client,
        kms: aws_sdk_kms::Client,
    ) -> Self {
        let clients = OnceCell::new();
        let _ = clients.set((s3, kms));
        Self {
            config,
            clients,
        }
    }

    /// Compute the full S3 object key for a logical reserve key.
    pub fn object_key(&self, key: &str) -> String {
        match self.config.prefix.as_deref() {
            Some(p) if !p.is_empty() => format!("{p}{key}"),
            _ => key.to_string(),
        }
    }

    /// Source bucket name. Useful for observability.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Return the cached AWS clients, building them on first call.
    async fn clients(&self) -> anyhow::Result<(aws_sdk_s3::Client, aws_sdk_kms::Client)> {
        let (s3, kms) = self.clients.get_or_init(|| async {
            let region = aws_sdk_s3::config::Region::new(self.config.region.clone());
            let aws_cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region)
                .load()
                .await;
            (aws_sdk_s3::Client::new(&aws_cfg), aws_sdk_kms::Client::new(&aws_cfg))
        }).await;
        Ok((s3.clone(), kms.clone()))
    }
}

// --- Envelope encryption helpers ---

/// Result of a `KMS:GenerateDataKey` call: a plaintext data key
/// (zeroized on drop) plus the wrapped (KMS-encrypted) form to store
/// alongside the ciphertext.
struct DataKey {
    plaintext: Zeroizing<[u8; AES256_KEY_LEN]>,
    wrapped: Vec<u8>,
}

async fn generate_data_key(kms: &aws_sdk_kms::Client, key_id: &str) -> anyhow::Result<DataKey> {
    let resp = kms
        .generate_data_key()
        .key_id(key_id)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %display_kms_err(&e), "KMS GenerateDataKey failed");
            anyhow::anyhow!("KMS GenerateDataKey failed")
        })?;
    let plaintext = resp
        .plaintext()
        .ok_or_else(|| anyhow::anyhow!("KMS GenerateDataKey: missing plaintext"))?
        .as_ref()
        .to_vec();
    let wrapped = resp
        .ciphertext_blob()
        .ok_or_else(|| anyhow::anyhow!("KMS GenerateDataKey: missing ciphertext_blob"))?
        .as_ref()
        .to_vec();
    let plaintext: [u8; AES256_KEY_LEN] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("KMS returned data key of unexpected length"))?;
    Ok(DataKey {
        plaintext: Zeroizing::new(plaintext),
        wrapped,
    })
}

async fn unwrap_data_key(
    kms: &aws_sdk_kms::Client,
    key_id: &str,
    wrapped: &[u8],
) -> anyhow::Result<Zeroizing<[u8; AES256_KEY_LEN]>> {
    let resp = kms
        .decrypt()
        .ciphertext_blob(Blob::new(wrapped.to_vec()))
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %display_kms_err(&e), "KMS Decrypt failed");
            anyhow::anyhow!("KMS Decrypt failed")
        })?;
    let plaintext = resp
        .plaintext()
        .ok_or_else(|| anyhow::anyhow!("KMS Decrypt: missing plaintext"))?
        .as_ref()
        .to_vec();
    let plaintext: [u8; AES256_KEY_LEN] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("KMS Decrypt returned key of unexpected length"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Scrub a KMS SDK error down to one line with no embedded newline.
/// The SDK never places key bytes in an error's `Display`, but this
/// keeps a future SDK revision from being trusted on that by default.
fn display_kms_err<E: std::fmt::Display>(e: &E) -> String {
    format!("{e}").replace('\n', " ")
}

// --- Metadata blob helpers ---

fn encode_meta_blob(metadata: &ReserveMetadata) -> anyhow::Result<String> {
    let json = serde_json::to_vec(metadata)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

fn decode_meta_blob(blob: &str) -> anyhow::Result<ReserveMetadata> {
    let json = base64::engine::general_purpose::STANDARD
        .decode(blob.as_bytes())
        .map_err(|e| anyhow::anyhow!("base64 decode reserve metadata: {e}"))?;
    serde_json::from_slice(&json).map_err(|e| anyhow::anyhow!("decode reserve metadata json: {e}"))
}

fn exceeds_size_limit(size: u64, limit: u64) -> bool {
    limit > 0 && size > limit
}

/// Build an unambiguous, versioned AAD value for one envelope.
///
/// Each component is length-prefixed, so no delimiter or concatenation
/// ambiguity can map two cache identities to the same authenticated
/// bytes. `meta_blob` is the exact base64 metadata value stored in S3;
/// changing status, headers, expiry, or any later `ReserveMetadata`
/// field therefore invalidates authentication before it is trusted.
fn envelope_aad_v2(
    config: &S3ReserveConfig,
    logical_key: &str,
    object_key: &str,
    meta_blob: &str,
) -> Vec<u8> {
    fn push_component(aad: &mut Vec<u8>, component: &[u8]) {
        aad.extend_from_slice(&(component.len() as u64).to_be_bytes());
        aad.extend_from_slice(component);
    }

    let prefix = config.prefix.as_deref().unwrap_or("");
    let mut aad = Vec::with_capacity(
        AAD_V2_DOMAIN.len()
            + config.bucket.len()
            + prefix.len()
            + logical_key.len()
            + object_key.len()
            + meta_blob.len()
            + 5 * std::mem::size_of::<u64>(),
    );
    aad.extend_from_slice(AAD_V2_DOMAIN);
    push_component(&mut aad, config.bucket.as_bytes());
    push_component(&mut aad, prefix.as_bytes());
    push_component(&mut aad, logical_key.as_bytes());
    push_component(&mut aad, object_key.as_bytes());
    push_component(&mut aad, meta_blob.as_bytes());
    aad
}

// --- Trait impl ---

#[async_trait]
impl CacheReserveBackend for S3Reserve {
    #[instrument(skip(self, value, metadata), fields(bucket = %self.config.bucket, size = value.len()))]
    async fn put(&self, key: &str, value: Bytes, metadata: ReserveMetadata) -> anyhow::Result<()> {
        if exceeds_size_limit(value.len() as u64, self.config.max_size_bytes) {
            return Err(anyhow::anyhow!(
                "S3 cache reserve value exceeds maximum object size"
            ));
        }
        let object_key = self.object_key(key);
        let meta_blob = encode_meta_blob(&metadata)?;
        let (s3, kms) = self.clients().await?;

        let mut user_meta: HashMap<String, String> = HashMap::new();
        let body_bytes = if self.config.sse_kms_bucket_default {
            // Plaintext upload; the bucket policy applies SSE-KMS.
            user_meta.insert(META_ENCRYPTION.to_string(), "sse-kms".to_string());
            value.to_vec()
        } else {
            let dk = generate_data_key(&kms, &self.config.kms_key_id).await?;
            let nonce = random_aes_gcm_nonce();
            let aad = envelope_aad_v2(&self.config, key, &object_key, &meta_blob);
            let ciphertext = aes256gcm_encrypt(&dk.plaintext, &nonce, &value, &aad)?;
            // The plaintext key's binding is dropped as soon as
            // encryption finishes; `Zeroizing` scrubs the bytes here
            // rather than leaving them for the allocator to reuse.
            drop(dk.plaintext);
            user_meta.insert(
                META_ENCRYPTION.to_string(),
                ENCRYPTION_ENVELOPE_V2.to_string(),
            );
            user_meta.insert(
                META_WRAPPED_KEY.to_string(),
                base64::engine::general_purpose::STANDARD.encode(&dk.wrapped),
            );
            user_meta.insert(
                META_NONCE.to_string(),
                base64::engine::general_purpose::STANDARD.encode(nonce),
            );
            ciphertext
        };
        user_meta.insert(META_META.to_string(), meta_blob);

        let mut req = s3
            .put_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .body(ByteStream::from(body_bytes));
        if let Some(ct) = metadata.content_type.as_deref() {
            req = req.content_type(ct);
        }
        if self.config.sse_kms_bucket_default {
            req = req
                .server_side_encryption(ServerSideEncryption::AwsKms)
                .ssekms_key_id(&self.config.kms_key_id);
        }
        for (k, v) in &user_meta {
            req = req.metadata(k, v);
        }

        match req.send().await {
            Ok(_) => {
                debug!(key = %key, object_key = %object_key, "cache reserve s3 put ok");
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("S3 PutObject failed: {e}")),
        }
    }

    #[instrument(skip(self), fields(bucket = %self.config.bucket))]
    async fn get(&self, key: &str) -> anyhow::Result<Option<(Bytes, ReserveMetadata)>> {
        let (s3, kms) = self.clients().await?;
        let object_key = self.object_key(key);

        let resp = s3
            .get_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                return match e.into_service_error() {
                    GetObjectError::NoSuchKey(_) => Ok(None),
                    other => Err(anyhow::anyhow!("S3 GetObject failed: {other}")),
                };
            }
        };

        let user_meta = resp.metadata().cloned();
        let meta_blob = user_meta
            .as_ref()
            .and_then(|m| m.get(META_META))
            .ok_or_else(|| anyhow::anyhow!("S3 object missing {META_META} metadata"))?;
        let metadata = decode_meta_blob(meta_blob)?;
        let mode = user_meta
            .as_ref()
            .and_then(|m| m.get(META_ENCRYPTION))
            .map(String::as_str);
        if mode.is_none() || mode == Some(ENCRYPTION_ENVELOPE_V1) {
            return Err(anyhow::anyhow!(
                "legacy S3 cache reserve envelope v1 is not key-bound; object must be rewritten"
            ));
        }
        if mode != Some("sse-kms") && mode != Some(ENCRYPTION_ENVELOPE_V2) {
            return Err(anyhow::anyhow!(
                "unsupported S3 cache reserve encryption version"
            ));
        }
        let stored_size_limit = if self.config.max_size_bytes == 0 {
            0
        } else if mode == Some("sse-kms") {
            self.config.max_size_bytes
        } else {
            self.config
                .max_size_bytes
                .saturating_add(AES_GCM_TAG_LEN)
        };
        if let Some(declared) = resp.content_length() {
            if declared < 0 || exceeds_size_limit(declared as u64, stored_size_limit) {
                return Err(anyhow::anyhow!(
                    "S3 cache reserve object exceeds maximum object size"
                ));
            }
        }
        let mut body = resp.body;
        let mut body_bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk
                .map_err(|e| anyhow::anyhow!("S3 GetObject body stream failed: {e}"))?;
            if exceeds_size_limit(
                (body_bytes.len() as u64).saturating_add(chunk.len() as u64),
                stored_size_limit,
            ) {
                return Err(anyhow::anyhow!(
                    "S3 cache reserve object exceeds maximum object size"
                ));
            }
            body_bytes.extend_from_slice(&chunk);
        }

        let plaintext = if mode == Some("sse-kms") {
            body_bytes
        } else {
            let wrapped_b64 = user_meta
                .as_ref()
                .and_then(|m| m.get(META_WRAPPED_KEY))
                .ok_or_else(|| anyhow::anyhow!("missing wrapped key on envelope object"))?;
            let nonce_b64 = user_meta
                .as_ref()
                .and_then(|m| m.get(META_NONCE))
                .ok_or_else(|| anyhow::anyhow!("missing nonce on envelope object"))?;
            let wrapped = base64::engine::general_purpose::STANDARD
                .decode(wrapped_b64.as_bytes())
                .map_err(|e| anyhow::anyhow!("base64 decode wrapped key: {e}"))?;
            let nonce_bytes = base64::engine::general_purpose::STANDARD
                .decode(nonce_b64.as_bytes())
                .map_err(|e| anyhow::anyhow!("base64 decode nonce: {e}"))?;
            let nonce: [u8; AES_GCM_NONCE_LEN] = nonce_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("nonce has wrong length"))?;
            let dk = unwrap_data_key(&kms, &self.config.kms_key_id, &wrapped).await?;
            let aad = envelope_aad_v2(&self.config, key, &object_key, meta_blob);
            aes256gcm_decrypt(&dk, &nonce, &body_bytes, &aad)?
        };

        if exceeds_size_limit(plaintext.len() as u64, self.config.max_size_bytes) {
            return Err(anyhow::anyhow!(
                "S3 cache reserve plaintext exceeds maximum object size"
            ));
        }

        debug!(key = %key, object_key = %object_key, size = plaintext.len(), "cache reserve s3 get ok");
        Ok(Some((Bytes::from(plaintext), metadata)))
    }

    #[instrument(skip(self), fields(bucket = %self.config.bucket))]
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let (s3, _kms) = self.clients().await?;
        let object_key = self.object_key(key);
        match s3
            .delete_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .send()
            .await
        {
            Ok(_) => {
                debug!(key = %key, object_key = %object_key, "cache reserve s3 delete ok");
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("S3 DeleteObject failed: {e}")),
        }
    }

    #[instrument(skip(self), fields(bucket = %self.config.bucket))]
    async fn evict_expired(&self, before: SystemTime) -> anyhow::Result<u64> {
        let (s3, _kms) = self.clients().await?;
        let mut continuation_token: Option<String> = None;
        let mut total_seen: u64 = 0;
        let mut total_deleted: u64 = 0;
        loop {
            let mut req = s3
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .max_keys(1000);
            if let Some(p) = self.config.prefix.as_deref() {
                if !p.is_empty() {
                    req = req.prefix(p);
                }
            }
            if let Some(t) = continuation_token.as_deref() {
                req = req.continuation_token(t);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("S3 ListObjectsV2 failed: {e}"))?;

            // Build the candidate set by HEAD-ing each object for its
            // metadata blob. This is the slowest path; production
            // deployments should rely on bucket lifecycle rules and
            // treat `evict_expired` as a backstop. See the warning
            // below once the bucket is large enough to make this a
            // real cost.
            let mut to_delete: Vec<ObjectIdentifier> = Vec::new();
            for obj in resp.contents() {
                total_seen += 1;
                let oid = match obj.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };
                let head = s3
                    .head_object()
                    .bucket(&self.config.bucket)
                    .key(&oid)
                    .send()
                    .await;
                let expired = match head {
                    Ok(h) => h
                        .metadata()
                        .and_then(|m| m.get(META_META))
                        .and_then(|b| decode_meta_blob(b).ok())
                        .map(|md| md.expires_at <= before)
                        .unwrap_or(false),
                    Err(head_err) => {
                        warn!(error = %head_err, key = %oid, "HEAD failed during evict; skipping");
                        false
                    }
                };
                if expired {
                    let id = ObjectIdentifier::builder()
                        .key(oid)
                        .build()
                        .map_err(|e| anyhow::anyhow!("build ObjectIdentifier: {e}"))?;
                    to_delete.push(id);
                }
            }

            if !to_delete.is_empty() {
                let count = to_delete.len() as u64;
                let delete = Delete::builder()
                    .set_objects(Some(to_delete))
                    .build()
                    .map_err(|e| anyhow::anyhow!("build Delete: {e}"))?;
                s3.delete_objects()
                    .bucket(&self.config.bucket)
                    .delete(delete)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("S3 DeleteObjects failed: {e}"))?;
                total_deleted += count;
            }

            if resp.is_truncated().unwrap_or(false) {
                continuation_token = resp.next_continuation_token().map(|s| s.to_string());
                if continuation_token.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        if total_seen > EVICT_OBJECT_WARN_THRESHOLD {
            warn!(
                bucket = %self.config.bucket,
                total_seen,
                "evict_expired iterated >100k objects; configure S3 lifecycle rules instead"
            );
        }

        Ok(total_deleted)
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config(prefix: Option<&str>) -> S3ReserveConfig {
        S3ReserveConfig {
            bucket: "test-bucket".into(),
            region: "us-west-2".into(),
            kms_key_id: "alias/test".into(),
            prefix: prefix.map(|s| s.to_string()),
            replication_target_bucket: None,
            sse_kms_bucket_default: false,
            max_size_bytes: 1_048_576,
        }
    }

    fn sample_reserve(prefix: Option<&str>) -> S3Reserve {
        // A no-network instance for object_key / Debug tests. The
        // clients are never dialed because these tests never call an
        // async trait method.
        use aws_sdk_s3::config::Region;
        let region = Region::new("us-west-2");
        let cfg_s3 = aws_sdk_s3::Config::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(region.clone())
            .build();
        let cfg_kms = aws_sdk_kms::Config::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(region)
            .build();
        S3Reserve::with_clients(
            sample_config(prefix),
            aws_sdk_s3::Client::from_conf(cfg_s3),
            aws_sdk_kms::Client::from_conf(cfg_kms),
        )
    }

    fn sample_metadata() -> ReserveMetadata {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        ReserveMetadata {
            created_at: now,
            expires_at: now + std::time::Duration::from_secs(3600),
            content_type: Some("application/json".into()),
            headers: vec![("etag".to_string(), r#"W/"v1""#.to_string())],
            vary_fingerprint: Some("v1".into()),
            size: 11,
            status: 200,
        }
    }

    #[test]
    fn object_key_with_prefix() {
        let r = sample_reserve(Some("reserve/"));
        assert_eq!(r.object_key("abc"), "reserve/abc");
    }

    #[test]
    fn object_key_without_prefix() {
        let r = sample_reserve(None);
        assert_eq!(r.object_key("abc"), "abc");
    }

    #[test]
    fn object_key_empty_prefix_skipped() {
        let r = sample_reserve(Some(""));
        assert_eq!(r.object_key("abc"), "abc");
    }

    #[test]
    fn bucket_returns_configured_name() {
        let r = sample_reserve(None);
        assert_eq!(r.bucket(), "test-bucket");
    }

    #[test]
    fn debug_formats_without_panic() {
        let r = sample_reserve(Some("reserve/"));
        let dbg = format!("{r:?}");
        assert!(dbg.contains("S3Reserve"));
        assert!(dbg.contains("us-west-2"));
    }

    #[test]
    fn new_rejects_empty_bucket() {
        let mut cfg = sample_config(None);
        cfg.bucket = String::new();
        assert!(S3Reserve::new(cfg).is_err());
    }

    #[test]
    fn new_rejects_empty_region() {
        let mut cfg = sample_config(None);
        cfg.region = String::new();
        assert!(S3Reserve::new(cfg).is_err());
    }

    #[test]
    fn new_rejects_empty_kms_key_id() {
        let mut cfg = sample_config(None);
        cfg.kms_key_id = String::new();
        assert!(S3Reserve::new(cfg).is_err());
    }

    #[test]
    fn new_accepts_a_well_formed_config() {
        assert!(S3Reserve::new(sample_config(Some("reserve/"))).is_ok());
    }

    #[test]
    fn meta_blob_round_trips_including_headers() {
        let md = sample_metadata();
        let blob = encode_meta_blob(&md).expect("encode");
        let decoded = decode_meta_blob(&blob).expect("decode");
        assert_eq!(decoded.status, md.status);
        assert_eq!(decoded.size, md.size);
        assert_eq!(decoded.content_type, md.content_type);
        assert_eq!(decoded.vary_fingerprint, md.vary_fingerprint);
        assert_eq!(decoded.headers, md.headers);
        assert_eq!(decoded.created_at, md.created_at);
        assert_eq!(decoded.expires_at, md.expires_at);
    }

    #[test]
    fn meta_blob_decode_rejects_invalid_base64() {
        assert!(decode_meta_blob("not base64!!").is_err());
    }

    #[test]
    fn meta_blob_decode_rejects_invalid_json() {
        let garbage = base64::engine::general_purpose::STANDARD.encode(b"not json");
        assert!(decode_meta_blob(&garbage).is_err());
    }

    #[test]
    fn kms_error_display_does_not_include_newlines() {
        struct E;
        impl std::fmt::Display for E {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "line1\nline2")
            }
        }
        let s = display_kms_err(&E);
        assert!(!s.contains('\n'));
    }
}

/// Mock-driven tests exercising the full `CacheReserveBackend` surface
/// against `aws_smithy_mocks` rather than a live S3 + KMS pair. Edge
/// cases specific to this file's internal layout (the single
/// `sbproxy-meta` blob) live here, alongside the constants they check
/// against; a black-box round trip through only the public API lives
/// in `tests/mock_s3_kms.rs`.
#[cfg(test)]
mod mock_trait_tests {
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use aws_sdk_kms::operation::decrypt::{DecryptError, DecryptOutput};
    use aws_sdk_kms::operation::generate_data_key::GenerateDataKeyOutput;
    use aws_sdk_kms::primitives::Blob as KmsBlob;
    use aws_sdk_s3::operation::delete_object::DeleteObjectOutput;
    use aws_sdk_s3::operation::delete_objects::DeleteObjectsOutput;
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::operation::head_object::HeadObjectOutput;
    use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::primitives::ByteStream;
    use aws_sdk_s3::types::Object;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};

    use super::*;

    /// Fixed 32-byte data key the KMS mock hands back.
    const FAKE_DATA_KEY: [u8; AES256_KEY_LEN] = [7u8; AES256_KEY_LEN];
    /// Fixed wrapped-key blob the KMS mock returns and accepts.
    const FAKE_WRAPPED_KEY: &[u8] = b"wrapped-data-key-blob-fixture";

    fn sample_config() -> S3ReserveConfig {
        S3ReserveConfig {
            bucket: "test-bucket".into(),
            region: "us-west-2".into(),
            kms_key_id: "alias/test".into(),
            prefix: Some("reserve/".into()),
            replication_target_bucket: None,
            sse_kms_bucket_default: false,
            max_size_bytes: 1_048_576,
        }
    }

    fn sample_metadata() -> ReserveMetadata {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        ReserveMetadata {
            created_at: now,
            expires_at: now + Duration::from_secs(3600),
            content_type: Some("application/json".into()),
            headers: vec![],
            vary_fingerprint: Some("v1".into()),
            size: 11,
            status: 200,
        }
    }

    fn meta_pairs(
        md: &ReserveMetadata,
        wrapped_b64: &str,
        nonce_b64: &str,
    ) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(META_META.to_string(), encode_meta_blob(md).expect("encode"));
        m.insert(
            META_ENCRYPTION.to_string(),
            ENCRYPTION_ENVELOPE_V2.to_string(),
        );
        m.insert(META_WRAPPED_KEY.to_string(), wrapped_b64.to_string());
        m.insert(META_NONCE.to_string(), nonce_b64.to_string());
        m
    }

    fn build_get_output(body: Vec<u8>, metadata: HashMap<String, String>) -> GetObjectOutput {
        let mut builder = GetObjectOutput::builder().body(ByteStream::from(body));
        for (k, v) in metadata {
            builder = builder.metadata(k, v);
        }
        builder.build()
    }

    fn sse_metadata() -> HashMap<String, String> {
        HashMap::from([
            (
                META_META.to_string(),
                encode_meta_blob(&sample_metadata()).expect("encode metadata"),
            ),
            (META_ENCRYPTION.to_string(), "sse-kms".to_string()),
        ])
    }

    #[tokio::test]
    async fn put_rejects_an_oversized_direct_backend_write_before_aws_calls() {
        let put_rule = mock!(aws_sdk_s3::Client::put_object)
            .then_output(|| PutObjectOutput::builder().build());
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_rule]);
        let generate_rule = mock!(aws_sdk_kms::Client::generate_data_key).then_output(|| {
            GenerateDataKeyOutput::builder()
                .plaintext(KmsBlob::new(FAKE_DATA_KEY.to_vec()))
                .ciphertext_blob(KmsBlob::new(FAKE_WRAPPED_KEY.to_vec()))
                .build()
        });
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&generate_rule]);
        let mut config = sample_config();
        config.max_size_bytes = 4;
        let reserve = S3Reserve::with_clients(config, s3, kms);

        let error = reserve
            .put("too-large", Bytes::from_static(b"12345"), sample_metadata())
            .await
            .expect_err("direct backend writes must enforce the object limit");

        assert!(format!("{error:#}").contains("maximum object size"));
        assert_eq!(generate_rule.num_calls(), 0, "KMS must not be called");
        assert_eq!(put_rule.num_calls(), 0, "S3 must not be called");
    }

    #[tokio::test]
    async fn get_rejects_an_oversized_declared_length_before_reading_the_body() {
        let get_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            let mut builder = GetObjectOutput::builder()
                .body(ByteStream::from(vec![0_u8; 5]))
                .content_length(5);
            for (key, value) in sse_metadata() {
                builder = builder.metadata(key, value);
            }
            builder.build()
        });
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);
        let kms_rule = mock!(aws_sdk_kms::Client::decrypt)
            .then_output(|| DecryptOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_rule]);
        let mut config = sample_config();
        config.max_size_bytes = 4;
        let reserve = S3Reserve::with_clients(config, s3, kms);

        let error = reserve
            .get("too-large")
            .await
            .expect_err("declared oversize must fail before body collection");

        assert!(format!("{error:#}").contains("maximum object size"));
        assert_eq!(kms_rule.num_calls(), 0, "KMS must not be called");
    }

    #[tokio::test]
    async fn get_caps_an_oversized_body_when_length_is_absent() {
        let get_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            let mut builder = GetObjectOutput::builder().body(ByteStream::from(vec![0_u8; 5]));
            for (key, value) in sse_metadata() {
                builder = builder.metadata(key, value);
            }
            builder.build()
        });
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);
        let kms_rule = mock!(aws_sdk_kms::Client::decrypt)
            .then_output(|| DecryptOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_rule]);
        let mut config = sample_config();
        config.max_size_bytes = 4;
        let reserve = S3Reserve::with_clients(config, s3, kms);

        let error = reserve
            .get("too-large")
            .await
            .expect_err("streaming oversize must fail at the hard cap");

        assert!(format!("{error:#}").contains("maximum object size"));
        assert_eq!(kms_rule.num_calls(), 0, "KMS must not be called");
    }

    #[tokio::test]
    async fn put_writes_meta_blob_and_invokes_kms_generate_data_key() {
        #[derive(Default, Clone)]
        struct Captured {
            bucket: Option<String>,
            key: Option<String>,
            metadata: Option<HashMap<String, String>>,
        }
        let captured: Arc<StdMutex<Captured>> = Arc::new(StdMutex::new(Captured::default()));
        let cap_for_rule = Arc::clone(&captured);

        let put_rule = mock!(aws_sdk_s3::Client::put_object).then_compute_output(move |req| {
            let mut g = cap_for_rule.lock().expect("lock");
            g.bucket = req.bucket().map(|s| s.to_string());
            g.key = req.key().map(|s| s.to_string());
            g.metadata = req.metadata().cloned();
            PutObjectOutput::builder().build()
        });
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_rule]);

        let gen_key_rule = mock!(aws_sdk_kms::Client::generate_data_key)
            .match_requests(|req| req.key_id() == Some("alias/test"))
            .then_output(|| {
                GenerateDataKeyOutput::builder()
                    .plaintext(KmsBlob::new(FAKE_DATA_KEY.to_vec()))
                    .ciphertext_blob(KmsBlob::new(FAKE_WRAPPED_KEY.to_vec()))
                    .key_id("alias/test")
                    .build()
            });
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&gen_key_rule]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        reserve
            .put("abc", Bytes::from_static(b"hello world"), sample_metadata())
            .await
            .expect("put");

        assert_eq!(gen_key_rule.num_calls(), 1, "GenerateDataKey call count");
        let cap = captured.lock().unwrap().clone();
        assert_eq!(cap.bucket.as_deref(), Some("test-bucket"));
        assert_eq!(cap.key.as_deref(), Some("reserve/abc"));
        let md = cap.metadata.expect("user metadata");
        assert!(md.contains_key(META_META), "meta blob present");
        assert!(md.contains_key(META_WRAPPED_KEY), "wrapped key present");
        assert!(md.contains_key(META_NONCE), "nonce present");
        assert_eq!(
            md.get(META_ENCRYPTION).map(String::as_str),
            Some(ENCRYPTION_ENVELOPE_V2),
        );
        let decoded = decode_meta_blob(md.get(META_META).unwrap()).expect("decode");
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.size, 11);
    }

    #[tokio::test]
    async fn an_envelope_copied_to_another_logical_key_fails_closed() {
        #[derive(Default, Clone)]
        struct CapturedObject {
            body: Vec<u8>,
            metadata: HashMap<String, String>,
        }

        let captured = Arc::new(StdMutex::new(CapturedObject::default()));
        let capture_for_put = Arc::clone(&captured);
        let put_rule = mock!(aws_sdk_s3::Client::put_object).then_compute_output(move |request| {
            let mut capture = capture_for_put.lock().expect("capture lock");
            capture.body = request
                .body()
                .bytes()
                .expect("in-memory put body")
                .to_vec();
            capture.metadata = request.metadata().cloned().unwrap_or_default();
            PutObjectOutput::builder().build()
        });
        let put_s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_rule]);
        let generate_rule = mock!(aws_sdk_kms::Client::generate_data_key).then_output(|| {
            GenerateDataKeyOutput::builder()
                .plaintext(KmsBlob::new(FAKE_DATA_KEY.to_vec()))
                .ciphertext_blob(KmsBlob::new(FAKE_WRAPPED_KEY.to_vec()))
                .key_id("alias/test")
                .build()
        });
        let put_kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&generate_rule]);
        let writer = S3Reserve::with_clients(sample_config(), put_s3, put_kms);
        writer
            .put("original", Bytes::from_static(b"hello world"), sample_metadata())
            .await
            .expect("write fixture");

        let copied = captured.lock().expect("capture lock").clone();
        let get_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|request| request.key() == Some("reserve/copied"))
            .then_output(move || build_get_output(copied.body.clone(), copied.metadata.clone()));
        let get_s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);
        let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt).then_output(|| {
            DecryptOutput::builder()
                .plaintext(KmsBlob::new(FAKE_DATA_KEY.to_vec()))
                .key_id("alias/test")
                .build()
        });
        let get_kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&decrypt_rule]);
        let reader = S3Reserve::with_clients(sample_config(), get_s3, get_kms);

        reader
            .get("copied")
            .await
            .expect_err("AAD must bind ciphertext to the exact logical and object key");
    }

    #[tokio::test]
    async fn get_decrypts_body_through_kms() {
        let nonce = random_aes_gcm_nonce();
        let plaintext = b"hello world";
        let config = sample_config();
        let meta_blob = encode_meta_blob(&sample_metadata()).expect("encode metadata");
        let aad = envelope_aad_v2(&config, "k", "reserve/k", &meta_blob);
        let ciphertext =
            aes256gcm_encrypt(&FAKE_DATA_KEY, &nonce, plaintext, &aad).expect("seal");

        let b64 = base64::engine::general_purpose::STANDARD;
        let metadata = meta_pairs(
            &sample_metadata(),
            &b64.encode(FAKE_WRAPPED_KEY),
            &b64.encode(nonce),
        );

        let get_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| {
                req.bucket() == Some("test-bucket") && req.key() == Some("reserve/k")
            })
            .then_output(move || build_get_output(ciphertext.clone(), metadata.clone()));
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);

        let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt)
            .match_requests(|req| req.ciphertext_blob().is_some())
            .then_output(|| {
                DecryptOutput::builder()
                    .plaintext(KmsBlob::new(FAKE_DATA_KEY.to_vec()))
                    .key_id("alias/test")
                    .build()
            });
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&decrypt_rule]);

        let reserve = S3Reserve::with_clients(config, s3, kms);
        let (body, md) = reserve.get("k").await.expect("get").expect("hit");
        assert_eq!(body.as_ref(), plaintext);
        assert_eq!(md.size, 11);
        assert_eq!(md.status, 200);
        assert_eq!(decrypt_rule.num_calls(), 1, "KMS Decrypt invoked once");
    }

    #[tokio::test]
    async fn get_returns_none_for_no_such_key() {
        use aws_sdk_s3::types::error::NoSuchKey;
        let get_rule = mock!(aws_sdk_s3::Client::get_object)
            .then_error(|| GetObjectError::NoSuchKey(NoSuchKey::builder().build()));
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);
        let kms_unused = mock!(aws_sdk_kms::Client::generate_data_key)
            .then_output(|| GenerateDataKeyOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_unused]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        let got = reserve.get("missing").await.expect("get ok");
        assert!(got.is_none(), "no-such-key must surface as Ok(None)");
    }

    #[tokio::test]
    async fn get_errors_when_meta_blob_missing() {
        let get_rule = mock!(aws_sdk_s3::Client::get_object)
            .then_output(|| build_get_output(vec![0u8; 16], HashMap::new()));
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);
        let kms_unused = mock!(aws_sdk_kms::Client::generate_data_key)
            .then_output(|| GenerateDataKeyOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_unused]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        let err = reserve.get("k").await.expect_err("must error");
        assert!(format!("{err:#}").contains(META_META));
    }

    #[tokio::test]
    async fn get_errors_when_wrapped_key_metadata_missing() {
        let mut metadata = meta_pairs(&sample_metadata(), "unused", "unused");
        metadata.remove(META_WRAPPED_KEY);
        let get_rule = mock!(aws_sdk_s3::Client::get_object)
            .then_output(move || build_get_output(vec![0u8; 16], metadata.clone()));
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);
        let kms_unused =
            mock!(aws_sdk_kms::Client::decrypt).then_output(|| DecryptOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_unused]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        let err = reserve.get("k").await.expect_err("must error");
        let msg = format!("{err:#}");
        assert!(msg.contains("wrapped key"), "got: {msg}");
        assert_eq!(kms_unused.num_calls(), 0, "KMS not called on missing meta");
    }

    #[tokio::test]
    async fn get_errors_when_nonce_metadata_missing() {
        let mut metadata = meta_pairs(&sample_metadata(), "d3JhcHBlZA==", "unused");
        metadata.remove(META_NONCE);
        let get_rule = mock!(aws_sdk_s3::Client::get_object)
            .then_output(move || build_get_output(vec![0u8; 16], metadata.clone()));
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);
        let kms_unused =
            mock!(aws_sdk_kms::Client::decrypt).then_output(|| DecryptOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_unused]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        let err = reserve.get("k").await.expect_err("must error");
        let msg = format!("{err:#}");
        assert!(msg.contains("nonce"), "got: {msg}");
        assert_eq!(kms_unused.num_calls(), 0, "KMS not called on missing meta");
    }

    #[tokio::test]
    async fn get_errors_when_kms_decrypt_fails() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let metadata = meta_pairs(
            &sample_metadata(),
            &b64.encode(FAKE_WRAPPED_KEY),
            &b64.encode([9u8; AES_GCM_NONCE_LEN]),
        );
        let get_rule = mock!(aws_sdk_s3::Client::get_object)
            .then_output(move || build_get_output(vec![0u8; 16], metadata.clone()));
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);

        let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt)
            .then_error(|| DecryptError::unhandled("simulated KMS failure"));
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&decrypt_rule]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        let err = reserve.get("k").await.expect_err("must error");
        assert!(format!("{err:#}").contains("KMS Decrypt"));
    }

    #[tokio::test]
    async fn delete_targets_correct_object_key() {
        let captured: Arc<StdMutex<Option<(String, String)>>> = Arc::new(StdMutex::new(None));
        let cap_for_rule = Arc::clone(&captured);
        let delete_rule =
            mock!(aws_sdk_s3::Client::delete_object).then_compute_output(move |req| {
                let mut g = cap_for_rule.lock().expect("lock");
                *g = Some((
                    req.bucket().unwrap_or("").to_string(),
                    req.key().unwrap_or("").to_string(),
                ));
                DeleteObjectOutput::builder().build()
            });
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&delete_rule]);
        let kms_unused = mock!(aws_sdk_kms::Client::generate_data_key)
            .then_output(|| GenerateDataKeyOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_unused]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        reserve.delete("zap").await.expect("delete ok");
        let (bucket, key) = captured.lock().unwrap().clone().expect("captured");
        assert_eq!(bucket, "test-bucket");
        assert_eq!(key, "reserve/zap");
        assert_eq!(kms_unused.num_calls(), 0, "KMS untouched on delete");
    }

    #[tokio::test]
    async fn evict_expired_deletes_only_stale_entries() {
        let stale_md = encode_meta_blob(&ReserveMetadata {
            created_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_672_531_200), // 2023-01-01
            content_type: None,
            headers: vec![],
            vary_fingerprint: None,
            size: 1,
            status: 200,
        })
        .expect("encode");
        let fresh_md = encode_meta_blob(&ReserveMetadata {
            created_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(4_070_908_800), // 2099-01-01
            content_type: None,
            headers: vec![],
            vary_fingerprint: None,
            size: 1,
            status: 200,
        })
        .expect("encode");

        let list_rule = mock!(aws_sdk_s3::Client::list_objects_v2)
            .match_requests(|req| req.bucket() == Some("test-bucket"))
            .then_output(|| {
                let stale = Object::builder().key("reserve/stale").build();
                let fresh = Object::builder().key("reserve/fresh").build();
                ListObjectsV2Output::builder()
                    .set_contents(Some(vec![stale, fresh]))
                    .is_truncated(false)
                    .build()
            });
        let head_stale = mock!(aws_sdk_s3::Client::head_object)
            .match_requests(|req| req.key() == Some("reserve/stale"))
            .then_output(move || {
                HeadObjectOutput::builder()
                    .metadata(META_META, stale_md.clone())
                    .build()
            });
        let head_fresh = mock!(aws_sdk_s3::Client::head_object)
            .match_requests(|req| req.key() == Some("reserve/fresh"))
            .then_output(move || {
                HeadObjectOutput::builder()
                    .metadata(META_META, fresh_md.clone())
                    .build()
            });
        let captured: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let cap_for_rule = Arc::clone(&captured);
        let delete_rule =
            mock!(aws_sdk_s3::Client::delete_objects).then_compute_output(move |req| {
                if let Some(d) = req.delete() {
                    let mut g = cap_for_rule.lock().expect("lock");
                    for o in d.objects() {
                        g.push(o.key().to_string());
                    }
                }
                DeleteObjectsOutput::builder().build()
            });

        let s3 = mock_client!(
            aws_sdk_s3,
            RuleMode::MatchAny,
            &[&list_rule, &head_stale, &head_fresh, &delete_rule]
        );
        let kms_unused = mock!(aws_sdk_kms::Client::generate_data_key)
            .then_output(|| GenerateDataKeyOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_unused]);

        let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(1_893_456_000); // 2030-01-01
        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        let n = reserve.evict_expired(cutoff).await.expect("evict ok");
        assert_eq!(n, 1, "exactly one expired entry deleted");
        assert_eq!(
            captured.lock().unwrap().clone(),
            vec!["reserve/stale".to_string()]
        );
        assert_eq!(list_rule.num_calls(), 1);
        assert_eq!(head_stale.num_calls(), 1);
        assert_eq!(head_fresh.num_calls(), 1);
        assert_eq!(delete_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn evict_expired_no_op_on_empty_bucket() {
        let list_rule = mock!(aws_sdk_s3::Client::list_objects_v2).then_output(|| {
            ListObjectsV2Output::builder()
                .set_contents(Some(vec![]))
                .is_truncated(false)
                .build()
        });
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&list_rule]);
        let kms_unused = mock!(aws_sdk_kms::Client::generate_data_key)
            .then_output(|| GenerateDataKeyOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_unused]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(1_893_456_000);
        let n = reserve.evict_expired(cutoff).await.expect("evict ok");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn evict_expired_skips_when_all_fresh() {
        let fresh_md = encode_meta_blob(&ReserveMetadata {
            created_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(4_070_908_800),
            content_type: None,
            headers: vec![],
            vary_fingerprint: None,
            size: 1,
            status: 200,
        })
        .expect("encode");
        let list_rule = mock!(aws_sdk_s3::Client::list_objects_v2).then_output(|| {
            let fresh = Object::builder().key("reserve/fresh").build();
            ListObjectsV2Output::builder()
                .set_contents(Some(vec![fresh]))
                .is_truncated(false)
                .build()
        });
        let head_rule = mock!(aws_sdk_s3::Client::head_object).then_output(move || {
            HeadObjectOutput::builder()
                .metadata(META_META, fresh_md.clone())
                .build()
        });
        let delete_rule = mock!(aws_sdk_s3::Client::delete_objects)
            .then_output(|| DeleteObjectsOutput::builder().build());
        let s3 = mock_client!(
            aws_sdk_s3,
            RuleMode::MatchAny,
            &[&list_rule, &head_rule, &delete_rule]
        );
        let kms_unused = mock!(aws_sdk_kms::Client::generate_data_key)
            .then_output(|| GenerateDataKeyOutput::builder().build());
        let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_unused]);

        let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
        let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(1_893_456_000);
        let n = reserve.evict_expired(cutoff).await.expect("evict ok");
        assert_eq!(n, 0);
        assert_eq!(delete_rule.num_calls(), 0, "DeleteObjects not invoked");
    }

    #[tokio::test]
    async fn sse_kms_mode_skips_envelope_encryption() {
        let put_rule = mock!(aws_sdk_s3::Client::put_object)
            .match_requests(|req| req.bucket() == Some("test-bucket"))
            .then_output(|| PutObjectOutput::builder().build());
        let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_rule]);

        let kms_must_not_be_called =
            mock!(aws_sdk_kms::Client::generate_data_key).then_error(|| {
                aws_sdk_kms::operation::generate_data_key::GenerateDataKeyError::unhandled(
                    "KMS must not be called in sse-kms mode",
                )
            });
        let kms = mock_client!(
            aws_sdk_kms,
            RuleMode::Sequential,
            &[&kms_must_not_be_called]
        );

        let cfg = S3ReserveConfig {
            sse_kms_bucket_default: true,
            ..sample_config()
        };
        let reserve = S3Reserve::with_clients(cfg, s3, kms);
        reserve
            .put("k", Bytes::from_static(b"plaintext"), sample_metadata())
            .await
            .expect("put");
    }
}

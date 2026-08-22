//! Black-box mock-based integration tests for [`S3Reserve`].
//!
//! Uses `aws-smithy-mocks` to stub the S3 + KMS SDK clients, so these
//! tests exercise the real request-building, envelope-encryption, and
//! response-parsing paths without a live AWS account or LocalStack.
//! Only the public API (`S3Reserve`, `S3ReserveConfig`,
//! `CacheReserveBackend`, `ReserveMetadata`) is exercised here; the
//! finer edge cases that need the module's private constants (a
//! missing wrapped key, a missing nonce, a corrupt metadata blob) live
//! in `crates/sbproxy-cache/src/reserve/s3.rs`'s own `mock_trait_tests`
//! module instead.

use std::time::{Duration, SystemTime};

use aws_sdk_kms::operation::decrypt::DecryptOutput;
use aws_sdk_kms::operation::generate_data_key::GenerateDataKeyOutput;
use aws_sdk_kms::primitives::Blob as KmsBlob;
use aws_sdk_s3::operation::delete_object::DeleteObjectOutput;
use aws_sdk_s3::operation::get_object::{GetObjectError, GetObjectOutput};
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::error::NoSuchKey;
use aws_smithy_mocks::{mock, mock_client, RuleMode};
use base64::Engine as _;
use bytes::Bytes;
use sbproxy_cache::{CacheReserveBackend, ReserveMetadata, S3Reserve, S3ReserveConfig};
use sbproxy_security::crypto::{aes256gcm_encrypt, AES256_KEY_LEN};

// --- Test helpers ---

fn sample_metadata() -> ReserveMetadata {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    ReserveMetadata {
        created_at: now,
        expires_at: now + Duration::from_secs(3600),
        content_type: Some("application/json".into()),
        headers: vec![("etag".to_string(), r#"W/"v1""#.to_string())],
        vary_fingerprint: Some("v1".into()),
        size: 11,
        status: 200,
    }
}

fn sample_config() -> S3ReserveConfig {
    S3ReserveConfig {
        bucket: "test-bucket".into(),
        region: "us-west-2".into(),
        kms_key_id: "alias/test".into(),
        prefix: Some("reserve/".into()),
        replication_target_bucket: None,
        sse_kms_bucket_default: false,
    }
}

/// The same `sbproxy-meta` encoding `S3Reserve::put` produces:
/// base64(json(metadata)). Duplicated here (rather than exposed from
/// the crate) because this file exercises only the public API.
fn encode_meta_blob(metadata: &ReserveMetadata) -> String {
    let json = serde_json::to_vec(metadata).expect("serialize metadata");
    base64::engine::general_purpose::STANDARD.encode(json)
}

/// Fixed 32-byte data key the KMS mock returns.
const FAKE_DATA_KEY: [u8; AES256_KEY_LEN] = [7u8; AES256_KEY_LEN];
/// Fixed wrapped-key blob the KMS mock returns and accepts.
const FAKE_WRAPPED_KEY: &[u8] = b"wrapped-data-key-blob-fixture";

// --- Tests ---

#[tokio::test]
async fn put_succeeds_with_envelope_encryption() {
    let put_rule = mock!(aws_sdk_s3::Client::put_object)
        .match_requests(|req| {
            req.bucket() == Some("test-bucket")
                && req.key() == Some("reserve/abc")
                && req.metadata().is_some()
        })
        .then_output(|| PutObjectOutput::builder().build());
    let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_rule]);

    let gen_key_rule = mock!(aws_sdk_kms::Client::generate_data_key).then_output(|| {
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
}

#[tokio::test]
async fn get_returns_none_for_no_such_key() {
    let get_rule = mock!(aws_sdk_s3::Client::get_object)
        .then_error(|| GetObjectError::NoSuchKey(NoSuchKey::builder().build()));
    let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&get_rule]);
    let gen_key_rule = mock!(aws_sdk_kms::Client::generate_data_key)
        .then_output(|| GenerateDataKeyOutput::builder().build());
    let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&gen_key_rule]);

    let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
    let got = reserve.get("missing").await.expect("get ok");
    assert!(got.is_none(), "no-such-key must surface as Ok(None)");
}

#[tokio::test]
async fn delete_invokes_s3_delete_object() {
    let delete_rule = mock!(aws_sdk_s3::Client::delete_object)
        .match_requests(|req| {
            req.bucket() == Some("test-bucket") && req.key() == Some("reserve/zap")
        })
        .then_output(|| DeleteObjectOutput::builder().build());
    let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&delete_rule]);
    // KMS client is required by the constructor but never invoked.
    let kms_dummy = mock!(aws_sdk_kms::Client::generate_data_key)
        .then_output(|| GenerateDataKeyOutput::builder().build());
    let kms = mock_client!(aws_sdk_kms, RuleMode::Sequential, &[&kms_dummy]);

    let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
    reserve.delete("zap").await.expect("delete ok");
}

#[tokio::test]
async fn put_then_get_round_trip_decrypts_body() {
    // We cannot easily share state between mock rules on two different
    // clients, so this precomputes the ciphertext `put` would have
    // produced given a deterministic data key + nonce, installs it as
    // the `GetObject` response, and confirms `get` decrypts it back to
    // the original plaintext.
    let nonce = [42u8; 12];
    let plaintext = b"hello world";
    let ciphertext = aes256gcm_encrypt(
        &FAKE_DATA_KEY,
        &nonce,
        plaintext,
        b"sbproxy-cache-reserve-s3-v1",
    )
    .expect("seal");

    let b64 = base64::engine::general_purpose::STANDARD;
    let metadata = sample_metadata();
    let meta_blob = encode_meta_blob(&metadata);
    let wrapped_b64 = b64.encode(FAKE_WRAPPED_KEY);
    let nonce_b64 = b64.encode(nonce);

    let get_rule = mock!(aws_sdk_s3::Client::get_object)
        .match_requests(|req| req.bucket() == Some("test-bucket") && req.key() == Some("reserve/k"))
        .then_output(move || {
            GetObjectOutput::builder()
                .body(ByteStream::from(ciphertext.clone()))
                .metadata("sbproxy-meta", meta_blob.clone())
                .metadata("sbproxy-encryption", "envelope-aes256gcm")
                .metadata("sbproxy-wrapped-key", wrapped_b64.clone())
                .metadata("sbproxy-nonce", nonce_b64.clone())
                .build()
        });
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

    let reserve = S3Reserve::with_clients(sample_config(), s3, kms);
    let got = reserve.get("k").await.expect("get ok").expect("hit");
    assert_eq!(got.0.as_ref(), plaintext.as_slice());
    assert_eq!(got.1.size, 11);
    assert_eq!(got.1.status, 200);
    assert_eq!(got.1.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        got.1.headers, metadata.headers,
        "headers round-trip through the meta blob"
    );
}

#[tokio::test]
async fn sse_kms_mode_skips_envelope_encryption() {
    // In SSE-KMS mode the body is uploaded plaintext; KMS should not
    // be called at all by `put`. Registering a KMS rule that errors if
    // invoked makes the assertion explicit rather than incidental.
    let put_rule = mock!(aws_sdk_s3::Client::put_object)
        .match_requests(|req| req.bucket() == Some("test-bucket"))
        .then_output(|| PutObjectOutput::builder().build());
    let s3 = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_rule]);

    let kms_must_not_be_called = mock!(aws_sdk_kms::Client::generate_data_key).then_error(|| {
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

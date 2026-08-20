//! JWE (RFC 7516) compact-serialization decryption for the `jwt` auth
//! provider (WOR-2520).
//!
//! Some enterprise IdPs (PingFederate, ForgeRock AM, Keycloak, Entra
//! ID with token encryption enabled) issue encrypted tokens: a signed
//! JWT nested inside a JWE (RFC 7519 section 5.2, decrypt-then-verify).
//! This module decrypts the outer JWE and hands the recovered payload
//! back to the existing JWS verification path; decryption alone never
//! authenticates anything, and every failure is refused with the same
//! outward behavior as a bad signature so a probing client cannot
//! distinguish "wrong key" from "wrong ciphertext".
//!
//! The supported algorithm set is the one those IdPs actually issue
//! for encrypted ID and access tokens, not the full JWA matrix:
//! `RSA-OAEP` and `RSA-OAEP-256` key unwrap, `ECDH-ES` direct key
//! agreement on P-256 (RFC 7518 section 4.6), and `A256GCM` content
//! encryption. Everything else is refused by name. `RSA1_5` stays
//! refused deliberately: it is vulnerable to Bleichenbacher-style
//! padding oracles and RFC 8725 section 3.1 tells receivers to avoid
//! it.
//!
//! Implemented over `aws-lc-rs`, which is already in the dependency
//! graph as `jsonwebtoken`'s crypto backend, rather than pulling a
//! JOSE crate (josekit binds OpenSSL, a second full crypto stack in a
//! workspace that deliberately runs on rustls/ring).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::Deserialize;

/// JWE decryption settings for the `jwt` auth provider (WOR-2520).
///
/// Present on a provider, it enables decrypt-then-verify handling of
/// five-segment JWE compact tokens; absent, JWE tokens are refused
/// exactly as before the feature existed. The nested payload is always
/// re-verified as a JWS with the provider's `secret` / `jwks_url`
/// machinery, so this never weakens what the provider accepts.
#[derive(Clone, Deserialize)]
pub struct JweConfig {
    /// PEM-encoded private key used to recover the content encryption
    /// key of an inbound JWE. An RSA private key (PKCS#8) enables the
    /// `RSA-OAEP` and `RSA-OAEP-256` algorithms; a P-256 EC private
    /// key (PKCS#8 or SEC1) enables `ECDH-ES`. Interpolate it from the
    /// environment or a secret backend (`${JWT_JWE_KEY}`) rather than
    /// committing key material to the config file.
    pub decryption_key: String,
}

/// Manual impl so the private key can never leak through debug
/// logging of the auth config (the `Auth` enum derives its debug
/// output from the provider structs).
impl std::fmt::Debug for JweConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JweConfig")
            .field("decryption_key", &"[redacted]")
            .finish()
    }
}

/// Why a JWE was refused.
///
/// Messages carry only public token header values (`alg`, `enc`) and
/// static phrases; they never echo key material, decrypted content, or
/// any configured value, so they are safe to log on the auth-failure
/// path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JweError {
    /// The token does not have the shape RFC 7516 requires.
    Malformed(&'static str),
    /// The `alg` header names a key-management algorithm outside the
    /// supported set. Carries the offending name for the log line.
    UnsupportedAlgorithm(String),
    /// The `enc` header names a content-encryption algorithm outside
    /// the supported set. Carries the offending name for the log line.
    UnsupportedEncryption(String),
    /// A header parameter we do not implement (`crit`, `zip`) is
    /// present; RFC 7516 section 4.1.11 requires refusal, and `zip`
    /// is refused rather than decompressed to keep decompression
    /// bombs out of the auth path.
    UnsupportedParameter(&'static str),
    /// The configured `decryption_key` could not be used as the key
    /// type the token's `alg` calls for. Static description only.
    KeyMismatch(&'static str),
    /// Key unwrap, key agreement, or AEAD open failed. Deliberately
    /// carries no detail: the caller logs it and refuses with the
    /// same challenge as a bad signature.
    DecryptionFailed,
}

impl std::fmt::Display for JweError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed JWE: {what}"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported JWE alg {alg:?}")
            }
            Self::UnsupportedEncryption(enc) => {
                write!(f, "unsupported JWE enc {enc:?}")
            }
            Self::UnsupportedParameter(name) => {
                write!(f, "unsupported JWE header parameter {name:?}")
            }
            Self::KeyMismatch(what) => write!(f, "JWE key mismatch: {what}"),
            Self::DecryptionFailed => write!(f, "JWE decryption failed"),
        }
    }
}

/// A256GCM nonce length in bytes (RFC 7518 section 5.3: 96-bit IV).
const A256GCM_IV_LEN: usize = 12;
/// A256GCM authentication tag length in bytes (128-bit tag).
const A256GCM_TAG_LEN: usize = 16;
/// A256GCM content-encryption key length in bytes.
const A256GCM_KEY_LEN: usize = 32;

/// Returns `true` when the token has the five-segment shape of a JWE
/// compact serialization (a JWS has three). Shape only; the segments
/// are validated by [`decrypt_compact`].
pub(crate) fn is_compact_jwe(token: &str) -> bool {
    token.bytes().filter(|b| *b == b'.').count() == 4
}

/// Decrypt a JWE compact serialization and return the plaintext,
/// which for a nested JWT is the inner JWS in its usual three-segment
/// form. The caller verifies that payload exactly like a directly
/// presented signed token; this function performs no signature checks
/// and grants nothing.
pub(crate) fn decrypt_compact(token: &str, config: &JweConfig) -> Result<String, JweError> {
    let mut segments = token.split('.');
    let (header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64) = match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some(h), Some(k), Some(i), Some(c), Some(t), None) => (h, k, i, c, t),
        _ => return Err(JweError::Malformed("expected five segments")),
    };

    let header_bytes = b64url(header_b64)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| JweError::Malformed("protected header is not JSON"))?;

    // RFC 7516 section 4.1.11: a receiver that does not understand a
    // `crit` extension MUST reject; we implement none, so any `crit`
    // is a rejection. `zip` (compressed plaintext) is refused rather
    // than inflated: attacker-sized decompression does not belong on
    // the authentication path.
    if header.get("crit").is_some() {
        return Err(JweError::UnsupportedParameter("crit"));
    }
    if header.get("zip").is_some() {
        return Err(JweError::UnsupportedParameter("zip"));
    }

    let alg = header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or(JweError::Malformed("missing alg header"))?;
    let enc = header
        .get("enc")
        .and_then(serde_json::Value::as_str)
        .ok_or(JweError::Malformed("missing enc header"))?;
    if enc != "A256GCM" {
        return Err(JweError::UnsupportedEncryption(enc.to_string()));
    }

    let encrypted_key = b64url(encrypted_key_b64)?;
    let iv = b64url(iv_b64)?;
    let ciphertext = b64url(ciphertext_b64)?;
    let tag = b64url(tag_b64)?;

    let key_der = pem_private_key_der(&config.decryption_key)?;

    let cek = match alg {
        "RSA-OAEP" => rsa_oaep_unwrap(
            &key_der,
            &encrypted_key,
            &aws_lc_rs::rsa::OAEP_SHA1_MGF1SHA1,
        )?,
        "RSA-OAEP-256" => rsa_oaep_unwrap(
            &key_der,
            &encrypted_key,
            &aws_lc_rs::rsa::OAEP_SHA256_MGF1SHA256,
        )?,
        "ECDH-ES" => ecdh_es_direct_cek(&key_der, &header, &encrypted_key)?,
        other => return Err(JweError::UnsupportedAlgorithm(other.to_string())),
    };
    if cek.len() != A256GCM_KEY_LEN {
        return Err(JweError::DecryptionFailed);
    }
    if iv.len() != A256GCM_IV_LEN {
        return Err(JweError::Malformed("A256GCM IV must be 96 bits"));
    }
    if tag.len() != A256GCM_TAG_LEN {
        return Err(JweError::Malformed("A256GCM tag must be 128 bits"));
    }

    // RFC 7516 section 5.1 step 14: the AAD is the ASCII bytes of the
    // base64url-encoded protected header, exactly as transmitted.
    let unbound = aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::AES_256_GCM, &cek)
        .map_err(|_| JweError::DecryptionFailed)?;
    let key = aws_lc_rs::aead::LessSafeKey::new(unbound);
    let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&iv)
        .map_err(|_| JweError::DecryptionFailed)?;
    let mut in_out = ciphertext;
    in_out.extend_from_slice(&tag);
    let plaintext = key
        .open_in_place(
            nonce,
            aws_lc_rs::aead::Aad::from(header_b64.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| JweError::DecryptionFailed)?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|_| JweError::Malformed("decrypted payload is not UTF-8"))
}

/// Base64url-decode one JWE segment. The error is a static phrase;
/// segment content is never echoed.
fn b64url(segment: &str) -> Result<Vec<u8>, JweError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| JweError::Malformed("segment is not base64url"))
}

/// Extract the DER bytes from the first PEM private-key block in the
/// configured `decryption_key`. The error is a static phrase; the key
/// text itself is never echoed.
fn pem_private_key_der(pem: &str) -> Result<Vec<u8>, JweError> {
    let mut in_block = false;
    let mut body = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") && line.contains("PRIVATE KEY") {
            in_block = true;
            continue;
        }
        // Only the END of the private-key block terminates the scan; a
        // preceding block of another kind (EC PARAMETERS, CERTIFICATE)
        // is skipped, not mistaken for the end of the key.
        if in_block && line.starts_with("-----END") {
            break;
        }
        if in_block {
            body.push_str(line);
        }
    }
    if !in_block || body.is_empty() {
        return Err(JweError::KeyMismatch(
            "decryption_key is not a PEM private key",
        ));
    }
    STANDARD
        .decode(body)
        .map_err(|_| JweError::KeyMismatch("decryption_key PEM body is not valid base64"))
}

/// Unwrap the content encryption key with RSA-OAEP (SHA-1 or SHA-256
/// per the `alg` header the caller matched on).
fn rsa_oaep_unwrap(
    key_der: &[u8],
    encrypted_key: &[u8],
    oaep: &'static aws_lc_rs::rsa::OaepAlgorithm,
) -> Result<Vec<u8>, JweError> {
    let private = aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8(key_der).map_err(|_| {
        JweError::KeyMismatch("token uses RSA-OAEP but decryption_key is not an RSA private key")
    })?;
    let private = aws_lc_rs::rsa::OaepPrivateDecryptingKey::new(private)
        .map_err(|_| JweError::DecryptionFailed)?;
    if encrypted_key.len() != private.key_size_bytes() {
        return Err(JweError::DecryptionFailed);
    }
    let mut out = vec![0u8; private.min_output_size()];
    let cek = private
        .decrypt(oaep, encrypted_key, &mut out, None)
        .map_err(|_| JweError::DecryptionFailed)?;
    Ok(cek.to_vec())
}

/// Derive the content encryption key for `ECDH-ES` direct agreement
/// (RFC 7518 section 4.6) on P-256: agree with the sender's ephemeral
/// public key from the `epk` header, then run the Concat KDF.
fn ecdh_es_direct_cek(
    key_der: &[u8],
    header: &serde_json::Value,
    encrypted_key: &[u8],
) -> Result<Vec<u8>, JweError> {
    // Direct key agreement: RFC 7518 section 4.6 requires an empty
    // encrypted-key segment. A non-empty one would be ECDH-ES+A*KW,
    // which carries its own alg names and is refused above by name.
    if !encrypted_key.is_empty() {
        return Err(JweError::Malformed(
            "ECDH-ES direct agreement must have an empty encrypted key",
        ));
    }
    let epk = header
        .get("epk")
        .ok_or(JweError::Malformed("missing epk header"))?;
    let crv = epk
        .get("crv")
        .and_then(serde_json::Value::as_str)
        .ok_or(JweError::Malformed("epk has no crv"))?;
    if crv != "P-256" {
        return Err(JweError::UnsupportedAlgorithm(format!("ECDH-ES on {crv}")));
    }
    let x = epk_coordinate(epk, "x")?;
    let y = epk_coordinate(epk, "y")?;
    // Uncompressed SEC1 point: 0x04 || X || Y.
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    let private = aws_lc_rs::agreement::PrivateKey::from_private_key_der(
        &aws_lc_rs::agreement::ECDH_P256,
        key_der,
    )
    .map_err(|_| {
        JweError::KeyMismatch("token uses ECDH-ES but decryption_key is not a P-256 private key")
    })?;
    let peer =
        aws_lc_rs::agreement::UnparsedPublicKey::new(&aws_lc_rs::agreement::ECDH_P256, &point);
    let shared = aws_lc_rs::agreement::agree(&private, peer, JweError::DecryptionFailed, |z| {
        Ok(z.to_vec())
    })?;

    let apu = header_b64_field(header, "apu")?;
    let apv = header_b64_field(header, "apv")?;
    Ok(concat_kdf_sha256(
        &shared,
        "A256GCM",
        &apu,
        &apv,
        (A256GCM_KEY_LEN * 8) as u32,
    ))
}

/// Decode one 32-byte base64url `epk` coordinate.
fn epk_coordinate(epk: &serde_json::Value, name: &'static str) -> Result<Vec<u8>, JweError> {
    let value = epk
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(JweError::Malformed("epk is missing a coordinate"))?;
    let bytes = b64url(value)?;
    if bytes.len() != 32 {
        return Err(JweError::Malformed("epk coordinate is not 32 bytes"));
    }
    Ok(bytes)
}

/// Decode an optional base64url header field (`apu` / `apv`), treating
/// absence as the empty string per RFC 7518 section 4.6.2.
fn header_b64_field(header: &serde_json::Value, name: &str) -> Result<Vec<u8>, JweError> {
    match header.get(name).and_then(serde_json::Value::as_str) {
        Some(value) => b64url(value),
        None => Ok(Vec::new()),
    }
}

/// The Concat KDF (NIST SP 800-56A section 5.8.1) with SHA-256, as
/// RFC 7518 section 4.6.2 profiles it for ECDH-ES: the per-round hash
/// input is a 32-bit big-endian counter, the shared secret Z, then
/// OtherInfo = (len || AlgorithmID) || (len || PartyUInfo) ||
/// (len || PartyVInfo) || SuppPubInfo(keybits).
fn concat_kdf_sha256(z: &[u8], alg_id: &str, apu: &[u8], apv: &[u8], key_bits: u32) -> Vec<u8> {
    use sha2::Digest as _;

    let mut other_info = Vec::new();
    for field in [alg_id.as_bytes(), apu, apv] {
        // The cast cannot truncate in practice: every field comes out
        // of the protected header, whose size the HTTP stack bounds
        // far below u32::MAX. A wrong length would only mis-derive
        // the key and fail the AEAD tag check, which refuses closed.
        other_info.extend_from_slice(&(field.len() as u32).to_be_bytes());
        other_info.extend_from_slice(field);
    }
    other_info.extend_from_slice(&key_bits.to_be_bytes());

    let key_len = (key_bits as usize).div_ceil(8);
    let mut derived = Vec::with_capacity(key_len);
    let mut round: u32 = 1;
    while derived.len() < key_len {
        let mut hasher = sha2::Sha256::new();
        hasher.update(round.to_be_bytes());
        hasher.update(z);
        hasher.update(&other_info);
        derived.extend_from_slice(&hasher.finalize());
        round += 1;
    }
    derived.truncate(key_len);
    derived
}

// --- Test support -----------------------------------------------------

/// JWE minting helpers for the unit tests here and the provider-level
/// tests in `auth::tests`. Test-only: production code never encrypts.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use aws_lc_rs::encoding::AsDer as _;

    /// Base64url-encode without padding.
    pub(crate) fn b64url_encode(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }

    /// Wrap DER bytes in a PKCS#8 PEM block.
    pub(crate) fn pem_wrap(der: &[u8]) -> String {
        let body = STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem
    }

    /// AES-256-GCM seal returning (ciphertext, tag).
    fn seal_a256gcm(
        cek: &[u8],
        iv: &[u8; A256GCM_IV_LEN],
        header_b64: &str,
        plaintext: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let unbound = aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::AES_256_GCM, cek).unwrap();
        let key = aws_lc_rs::aead::LessSafeKey::new(unbound);
        let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(*iv);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(
            nonce,
            aws_lc_rs::aead::Aad::from(header_b64.as_bytes()),
            &mut in_out,
        )
        .unwrap();
        let tag = in_out.split_off(in_out.len() - A256GCM_TAG_LEN);
        (in_out, tag)
    }

    /// Assemble the five-segment compact serialization.
    fn assemble(
        header_b64: &str,
        encrypted_key: &[u8],
        iv: &[u8],
        ct: &[u8],
        tag: &[u8],
    ) -> String {
        format!(
            "{}.{}.{}.{}.{}",
            header_b64,
            b64url_encode(encrypted_key),
            b64url_encode(iv),
            b64url_encode(ct),
            b64url_encode(tag)
        )
    }

    /// Mint an RSA JWE around `plaintext`. Returns the compact token
    /// and the receiver's private key PEM. `alg` picks the OAEP hash:
    /// `RSA-OAEP` (SHA-1) or `RSA-OAEP-256` (SHA-256).
    pub(crate) fn mint_rsa_jwe(plaintext: &str, alg: &str) -> (String, String) {
        let private =
            aws_lc_rs::rsa::PrivateDecryptingKey::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
                .unwrap();
        let pem = pem_wrap(private.as_der().unwrap().as_ref());
        let public = aws_lc_rs::rsa::OaepPublicEncryptingKey::new(private.public_key()).unwrap();
        let oaep = match alg {
            "RSA-OAEP" => &aws_lc_rs::rsa::OAEP_SHA1_MGF1SHA1,
            "RSA-OAEP-256" => &aws_lc_rs::rsa::OAEP_SHA256_MGF1SHA256,
            other => panic!("unsupported test alg {other}"),
        };

        let mut cek = [0u8; A256GCM_KEY_LEN];
        aws_lc_rs::rand::fill(&mut cek).unwrap();
        let mut iv = [0u8; A256GCM_IV_LEN];
        aws_lc_rs::rand::fill(&mut iv).unwrap();

        let header = serde_json::json!({"alg": alg, "enc": "A256GCM", "cty": "JWT"});
        let header_b64 = b64url_encode(header.to_string().as_bytes());

        let mut wrapped = vec![0u8; public.ciphertext_size()];
        let wrapped = public
            .encrypt(oaep, &cek, &mut wrapped, None)
            .unwrap()
            .to_vec();

        let (ct, tag) = seal_a256gcm(&cek, &iv, &header_b64, plaintext.as_bytes());
        (assemble(&header_b64, &wrapped, &iv, &ct, &tag), pem)
    }

    /// Mint an ECDH-ES (direct agreement, P-256, A256GCM) JWE around
    /// `plaintext`. Returns the compact token and the receiver's
    /// private key PEM.
    pub(crate) fn mint_ecdh_es_jwe(plaintext: &str) -> (String, String) {
        let receiver =
            aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::ECDH_P256).unwrap();
        let receiver_pub = receiver.compute_public_key().unwrap();
        let pkcs8: aws_lc_rs::encoding::Pkcs8V1Der = receiver.as_der().unwrap();
        let pem = pem_wrap(pkcs8.as_ref());

        let ephemeral =
            aws_lc_rs::agreement::PrivateKey::generate(&aws_lc_rs::agreement::ECDH_P256).unwrap();
        let ephemeral_pub = ephemeral.compute_public_key().unwrap();
        // Uncompressed point 0x04 || X || Y.
        let point = ephemeral_pub.as_ref();
        assert_eq!(point.len(), 65);
        let header = serde_json::json!({
            "alg": "ECDH-ES",
            "enc": "A256GCM",
            "cty": "JWT",
            "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": b64url_encode(&point[1..33]),
                "y": b64url_encode(&point[33..65]),
            },
        });
        let header_b64 = b64url_encode(header.to_string().as_bytes());

        let receiver_point = aws_lc_rs::agreement::UnparsedPublicKey::new(
            &aws_lc_rs::agreement::ECDH_P256,
            receiver_pub.as_ref().to_vec(),
        );
        let z = aws_lc_rs::agreement::agree(&ephemeral, &receiver_point, (), |z| {
            Ok::<_, ()>(z.to_vec())
        })
        .unwrap();
        let cek = concat_kdf_sha256(&z, "A256GCM", &[], &[], (A256GCM_KEY_LEN * 8) as u32);

        let mut iv = [0u8; A256GCM_IV_LEN];
        aws_lc_rs::rand::fill(&mut iv).unwrap();
        let (ct, tag) = seal_a256gcm(&cek, &iv, &header_b64, plaintext.as_bytes());
        (assemble(&header_b64, &[], &iv, &ct, &tag), pem)
    }
}

// --- Tests -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn config(pem: &str) -> JweConfig {
        JweConfig {
            decryption_key: pem.to_string(),
        }
    }

    #[test]
    fn concat_kdf_matches_rfc7518_appendix_c_vector() {
        // RFC 7518 Appendix C: ECDH-ES direct agreement, enc A128GCM,
        // apu "Alice", apv "Bob", 128-bit output.
        let z: [u8; 32] = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let derived = concat_kdf_sha256(&z, "A128GCM", b"Alice", b"Bob", 128);
        assert_eq!(b64url_encode(&derived), "VqqN6vgjbSBcIijNcacQGg");
    }

    #[test]
    fn rsa_oaep_roundtrip() {
        let (token, pem) = mint_rsa_jwe("payload.jws.here", "RSA-OAEP");
        assert!(is_compact_jwe(&token));
        let plain = decrypt_compact(&token, &config(&pem)).unwrap();
        assert_eq!(plain, "payload.jws.here");
    }

    #[test]
    fn rsa_oaep_256_roundtrip() {
        let (token, pem) = mint_rsa_jwe("payload.jws.here", "RSA-OAEP-256");
        let plain = decrypt_compact(&token, &config(&pem)).unwrap();
        assert_eq!(plain, "payload.jws.here");
    }

    #[test]
    fn ecdh_es_roundtrip() {
        let (token, pem) = mint_ecdh_es_jwe("payload.jws.here");
        let plain = decrypt_compact(&token, &config(&pem)).unwrap();
        assert_eq!(plain, "payload.jws.here");
    }

    #[test]
    fn garbage_ciphertext_refused() {
        let (token, pem) = mint_rsa_jwe("payload", "RSA-OAEP");
        let mut parts: Vec<&str> = token.split('.').collect();
        let garbage = b64url_encode(&[0xA5; 40]);
        parts[3] = &garbage;
        let tampered = parts.join(".");
        assert_eq!(
            decrypt_compact(&tampered, &config(&pem)),
            Err(JweError::DecryptionFailed)
        );
    }

    #[test]
    fn tampered_tag_refused() {
        let (token, pem) = mint_rsa_jwe("payload", "RSA-OAEP");
        let mut parts: Vec<&str> = token.split('.').collect();
        let bogus_tag = b64url_encode(&[0x5A; A256GCM_TAG_LEN]);
        parts[4] = &bogus_tag;
        let tampered = parts.join(".");
        assert_eq!(
            decrypt_compact(&tampered, &config(&pem)),
            Err(JweError::DecryptionFailed)
        );
    }

    #[test]
    fn unsupported_alg_refused_naming_the_alg() {
        // RSA1_5 is the classic padding-oracle-prone alg (RFC 8725
        // section 3.1); the refusal must name it so the operator can
        // see what the IdP is issuing.
        let (token, pem) = mint_rsa_jwe("payload", "RSA-OAEP");
        let mut parts: Vec<&str> = token.split('.').collect();
        let header = b64url_encode(br#"{"alg":"RSA1_5","enc":"A256GCM"}"#);
        parts[0] = &header;
        let swapped = parts.join(".");
        let err = decrypt_compact(&swapped, &config(&pem)).unwrap_err();
        assert_eq!(err, JweError::UnsupportedAlgorithm("RSA1_5".to_string()));
        assert!(format!("{err}").contains("RSA1_5"));
    }

    #[test]
    fn unsupported_enc_refused_naming_the_enc() {
        let (token, pem) = mint_rsa_jwe("payload", "RSA-OAEP");
        let mut parts: Vec<&str> = token.split('.').collect();
        let header = b64url_encode(br#"{"alg":"RSA-OAEP","enc":"A128CBC-HS256"}"#);
        parts[0] = &header;
        let swapped = parts.join(".");
        let err = decrypt_compact(&swapped, &config(&pem)).unwrap_err();
        assert!(format!("{err}").contains("A128CBC-HS256"));
    }

    #[test]
    fn zip_and_crit_headers_refused() {
        let (token, pem) = mint_rsa_jwe("payload", "RSA-OAEP");
        let parts: Vec<&str> = token.split('.').collect();
        for (header, expect) in [
            (
                b64url_encode(br#"{"alg":"RSA-OAEP","enc":"A256GCM","zip":"DEF"}"#),
                "zip",
            ),
            (
                b64url_encode(br#"{"alg":"RSA-OAEP","enc":"A256GCM","crit":["exp"]}"#),
                "crit",
            ),
        ] {
            let mut swapped = parts.clone();
            swapped[0] = &header;
            let err = decrypt_compact(&swapped.join("."), &config(&pem)).unwrap_err();
            assert_eq!(err, JweError::UnsupportedParameter(expect));
        }
    }

    #[test]
    fn wrong_key_type_refused_without_echoing_the_key() {
        // ECDH-ES token, RSA key configured: refused, and the error
        // text must not contain any part of the configured PEM.
        let (token, _) = mint_ecdh_es_jwe("payload");
        let (_, rsa_pem) = mint_rsa_jwe("x", "RSA-OAEP");
        let err = decrypt_compact(&token, &config(&rsa_pem)).unwrap_err();
        let msg = format!("{err} {err:?}");
        let pem_body: Vec<&str> = rsa_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        for line in pem_body {
            assert!(!msg.contains(line), "error text leaked key material");
        }
        assert_eq!(
            err,
            JweError::KeyMismatch(
                "token uses ECDH-ES but decryption_key is not a P-256 private key"
            )
        );
    }

    #[test]
    fn pem_with_leading_parameters_block_still_parses() {
        // `openssl ecparam -genkey` emits an EC PARAMETERS block ahead
        // of the key; the scan must skip it rather than stop at its
        // END line.
        let (token, pem) = mint_ecdh_es_jwe("payload");
        let wrapped = format!(
            "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n{pem}"
        );
        assert_eq!(
            decrypt_compact(&token, &config(&wrapped)).unwrap(),
            "payload"
        );
    }

    #[test]
    fn non_pem_key_refused() {
        let (token, _) = mint_rsa_jwe("payload", "RSA-OAEP");
        let err = decrypt_compact(&token, &config("not a pem at all")).unwrap_err();
        assert_eq!(
            err,
            JweError::KeyMismatch("decryption_key is not a PEM private key")
        );
    }

    #[test]
    fn ecdh_es_with_wrapped_key_segment_refused() {
        // A non-empty encrypted-key segment under alg ECDH-ES is not
        // direct agreement; refuse instead of ignoring the segment.
        let (token, pem) = mint_ecdh_es_jwe("payload");
        let mut parts: Vec<&str> = token.split('.').collect();
        let bogus_key = b64url_encode(&[1u8; 32]);
        parts[1] = &bogus_key;
        let err = decrypt_compact(&parts.join("."), &config(&pem)).unwrap_err();
        assert_eq!(
            err,
            JweError::Malformed("ECDH-ES direct agreement must have an empty encrypted key")
        );
    }

    #[test]
    fn is_compact_jwe_counts_segments() {
        assert!(is_compact_jwe("a.b.c.d.e"));
        assert!(!is_compact_jwe("a.b.c"));
        assert!(!is_compact_jwe("a.b.c.d"));
        assert!(!is_compact_jwe("a.b.c.d.e.f"));
    }

    #[test]
    fn debug_never_prints_the_key() {
        let cfg = config("-----BEGIN PRIVATE KEY-----\nSECRETMATERIAL\n-----END PRIVATE KEY-----");
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("SECRETMATERIAL"));
        assert!(debug.contains("[redacted]"));
    }
}

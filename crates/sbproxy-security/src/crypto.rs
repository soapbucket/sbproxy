//! HKDF key derivation and cryptographic helpers.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive a key using HKDF-SHA256 (RFC 5869).
///
/// - `ikm`: Input keying material.
/// - `salt`: Optional salt value (can be empty).
/// - `info`: Context and application-specific info string.
/// - `output_len`: Desired output length in bytes (max 255 * 32).
pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    let prk = hmac_sha256(salt, ikm);
    // Expand
    hkdf_expand(&prk, info, output_len)
}

/// HMAC-SHA256 backed by the audited `hmac` crate (RFC 2104).
///
/// `Hmac::<Sha256>::new_from_slice` accepts keys of any length and
/// applies the same key shortening / padding that RFC 2104 specifies
/// internally, so callers do not need to pre-hash long keys.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // new_from_slice only fails for invalid key lengths on fixed-key MACs;
    // HMAC-SHA256 accepts any key length, so this never errors in practice.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HKDF-Expand step per RFC 5869.
fn hkdf_expand(prk: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let hash_len = 32; // SHA-256 output
    let n = output_len.div_ceil(hash_len);
    let mut okm = Vec::with_capacity(output_len);
    let mut prev = Vec::new();

    for i in 1..=n {
        let mut input = Vec::new();
        input.extend_from_slice(&prev);
        input.extend_from_slice(info);
        input.push(i as u8);
        prev = hmac_sha256(prk, &input);
        okm.extend_from_slice(&prev);
    }

    okm.truncate(output_len);
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive_produces_correct_length() {
        let key = hkdf_derive(b"secret", b"salt", b"info", 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_derive_deterministic() {
        let k1 = hkdf_derive(b"secret", b"salt", b"info", 32);
        let k2 = hkdf_derive(b"secret", b"salt", b"info", 32);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_hkdf_different_info_produces_different_keys() {
        let k1 = hkdf_derive(b"secret", b"salt", b"encryption", 32);
        let k2 = hkdf_derive(b"secret", b"salt", b"signing", 32);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_hkdf_different_lengths() {
        let k16 = hkdf_derive(b"secret", b"salt", b"info", 16);
        let k64 = hkdf_derive(b"secret", b"salt", b"info", 64);
        assert_eq!(k16.len(), 16);
        assert_eq!(k64.len(), 64);
        // First 16 bytes should match
        assert_eq!(&k16[..], &k64[..16]);
    }

    #[test]
    fn test_hmac_sha256_basic() {
        // Verify HMAC produces a 32-byte output
        let mac = hmac_sha256(b"key", b"data");
        assert_eq!(mac.len(), 32);
        // Verify it is deterministic
        assert_eq!(mac, hmac_sha256(b"key", b"data"));
    }

    // --- Known-Answer Tests (RFC 4231 / RFC 5869) ---
    //
    // These vectors lock the byte-for-byte output of `hmac_sha256` and
    // `hkdf_derive`. They were captured against the hand-rolled RFC 2104
    // implementation that previously lived in this file, and they continue
    // to hold after the swap to the audited `hmac` crate.

    #[test]
    fn kat_rfc4231_test_case_1() {
        // Key: 20 bytes of 0x0b. Data: "Hi There".
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = hex_decode(
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7",
        );
        assert_eq!(hmac_sha256(&key, data), expected);
    }

    #[test]
    fn kat_rfc4231_test_case_2() {
        // Key: "Jefe". Data: "what do ya want for nothing?".
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex_decode(
            "5bdcc146bf60754e6a042426089575c7\
             5a003f089d2739839dec58b964ec3843",
        );
        assert_eq!(hmac_sha256(key, data), expected);
    }

    #[test]
    fn kat_rfc4231_test_case_3() {
        // Key: 20 bytes of 0xaa. Data: 50 bytes of 0xdd.
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let expected = hex_decode(
            "773ea91e36800e46854db8ebd09181a7\
             2959098b3ef8c122d9635514ced565fe",
        );
        assert_eq!(hmac_sha256(&key, &data), expected);
    }

    #[test]
    fn kat_rfc4231_test_case_6_long_key() {
        // Key: 131 bytes of 0xaa, longer than the 64-byte block. The
        // implementation must hash the key down before keying HMAC.
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex_decode(
            "60e431591ee0b67f0d8a26aacbf5b77f\
             8e0bc6213728c5140546040f0ee37f54",
        );
        assert_eq!(hmac_sha256(&key, data), expected);
    }

    #[test]
    fn kat_hkdf_rfc5869_test_case_1() {
        // HKDF-SHA256 vector from RFC 5869 Appendix A.1.
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );
        let okm = hkdf_derive(&ikm, &salt, &info, 42);
        assert_eq!(okm, expected_okm);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(cleaned).expect("valid hex")
    }
}

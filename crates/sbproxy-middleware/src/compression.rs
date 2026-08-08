//! Response compression content negotiation and encoding.
//!
//! Parses `Accept-Encoding` and selects the best compression algorithm
//! supported by both the client and the [`CompressionConfig`], then
//! compresses the response body with that algorithm.

use std::io::Write;

use sbproxy_config::CompressionConfig;

/// Supported compression encodings, ordered by preference (best first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Zstandard compression (`zstd`), best ratio when supported.
    Zstd,
    /// Brotli compression (`br`).
    Brotli,
    /// Gzip compression (`gzip`).
    Gzip,
    /// No compression (`identity`).
    Identity,
}

impl Encoding {
    /// Returns the value to use in the `Content-Encoding` header.
    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::Zstd => "zstd",
            Encoding::Brotli => "br",
            Encoding::Gzip => "gzip",
            Encoding::Identity => "identity",
        }
    }
}

/// Select the best encoding based on `Accept-Encoding` header and config.
///
/// Preference order when multiple algorithms are acceptable: zstd > br > gzip.
/// Returns [`Encoding::Identity`] when compression is disabled, the client does
/// not accept any configured algorithm, or `accept_encoding` is absent.
pub fn negotiate_encoding(config: &CompressionConfig, accept_encoding: Option<&str>) -> Encoding {
    if !config.enabled {
        return Encoding::Identity;
    }

    let accept = match accept_encoding {
        Some(s) if !s.is_empty() => s,
        _ => return Encoding::Identity,
    };

    let algo_allowed = |name: &str| -> bool {
        config.algorithms.is_empty() || config.algorithms.iter().any(|a| a == name)
    };

    // Check in preference order: zstd > br > gzip
    // We do a simple substring check per token. A production implementation
    // would parse quality values, but this is sufficient for Phase 2.
    if algo_allowed("zstd") && accepts(accept, "zstd") {
        Encoding::Zstd
    } else if algo_allowed("br") && accepts(accept, "br") {
        Encoding::Brotli
    } else if algo_allowed("gzip") && accepts(accept, "gzip") {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

/// Check whether the Accept-Encoding header value contains a given token.
///
/// Handles comma-separated values and avoids false substring matches
/// (e.g. "br" should not match inside "brotli-custom").
fn accepts(accept_encoding: &str, token: &str) -> bool {
    accept_encoding.split(',').any(|part| {
        let part = part.split(';').next().unwrap_or("").trim();
        part.eq_ignore_ascii_case(token) || part == "*"
    })
}

/// Default content-type prefixes that should not be re-compressed.
///
/// These types are already compressed at the format level, so a second
/// pass burns CPU without shrinking bytes (and often grows them).
const SKIP_CONTENT_TYPE_PREFIXES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/heic",
    "image/heif",
    "video/",
    "audio/",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/zstd",
    "application/wasm",
    "application/octet-stream",
    "font/woff",
    "font/woff2",
];

/// Whether a response with the given `Content-Type` should be compressed.
///
/// Returns `false` for already-compressed media types (images, video,
/// audio, archives, etc.). When `content_type` is `None` we assume the
/// response is text-shaped and allow compression.
pub fn should_compress_content_type(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return true;
    };
    let primary = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    !SKIP_CONTENT_TYPE_PREFIXES
        .iter()
        .any(|prefix| primary.starts_with(prefix))
}

/// Compress `body` using the chosen [`Encoding`].
///
/// Returns the original bytes unchanged for [`Encoding::Identity`]. `level`
/// carries the origin's `compression.level` and is clamped into each
/// library's native range (gzip 0-9, brotli quality 0-11, zstd 1-22), so
/// one configured value stays meaningful whichever algorithm the client
/// negotiates. When `level` is `None` the gzip and zstd writers use their
/// crates' default compression level and the brotli encoder uses quality 4
/// (a balance between throughput and ratio that matches what most reverse
/// proxies ship by default).
pub fn compress_body(
    body: &[u8],
    encoding: Encoding,
    level: Option<u32>,
) -> std::io::Result<Vec<u8>> {
    match encoding {
        Encoding::Identity => Ok(body.to_vec()),
        Encoding::Gzip => {
            let compression = match level {
                Some(value) => flate2::Compression::new(value.min(9)),
                None => flate2::Compression::default(),
            };
            let mut enc =
                flate2::write::GzEncoder::new(Vec::with_capacity(body.len()), compression);
            enc.write_all(body)?;
            enc.finish()
        }
        Encoding::Brotli => {
            let quality = level.map_or(4, |value| value.min(11));
            let mut out = Vec::with_capacity(body.len());
            let mut writer = brotli::CompressorWriter::new(&mut out, 4096, quality, 22);
            writer.write_all(body)?;
            writer.flush()?;
            drop(writer);
            Ok(out)
        }
        Encoding::Zstd => {
            let level = level.map_or(0, |value| value.clamp(1, 22)) as i32;
            zstd::encode_all(body, level)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> CompressionConfig {
        CompressionConfig {
            enabled: true,
            algorithms: vec![],
            min_size: 0,
            level: None,
        }
    }

    // --- Disabled ---

    #[test]
    fn test_disabled_returns_identity() {
        let config = CompressionConfig {
            enabled: false,
            algorithms: vec![],
            min_size: 0,
            level: None,
        };
        assert_eq!(
            negotiate_encoding(&config, Some("gzip, br, zstd")),
            Encoding::Identity
        );
    }

    // --- No Accept-Encoding ---

    #[test]
    fn test_no_accept_encoding_returns_identity() {
        assert_eq!(
            negotiate_encoding(&enabled_config(), None),
            Encoding::Identity
        );
    }

    #[test]
    fn test_empty_accept_encoding_returns_identity() {
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("")),
            Encoding::Identity
        );
    }

    // --- Preference Order ---

    #[test]
    fn test_prefers_zstd_over_br_and_gzip() {
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("gzip, br, zstd")),
            Encoding::Zstd
        );
    }

    #[test]
    fn test_prefers_br_over_gzip() {
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("gzip, br")),
            Encoding::Brotli
        );
    }

    #[test]
    fn test_falls_back_to_gzip() {
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("gzip")),
            Encoding::Gzip
        );
    }

    // --- Config restricts algorithms ---

    #[test]
    fn test_config_restricts_to_gzip_only() {
        let config = CompressionConfig {
            enabled: true,
            algorithms: vec!["gzip".into()],
            min_size: 0,
            level: None,
        };
        assert_eq!(
            negotiate_encoding(&config, Some("gzip, br, zstd")),
            Encoding::Gzip
        );
    }

    #[test]
    fn test_config_restricts_to_br_only() {
        let config = CompressionConfig {
            enabled: true,
            algorithms: vec!["br".into()],
            min_size: 0,
            level: None,
        };
        assert_eq!(
            negotiate_encoding(&config, Some("gzip, br, zstd")),
            Encoding::Brotli
        );
    }

    #[test]
    fn test_no_matching_algorithm() {
        let config = CompressionConfig {
            enabled: true,
            algorithms: vec!["zstd".into()],
            min_size: 0,
            level: None,
        };
        assert_eq!(
            negotiate_encoding(&config, Some("gzip, br")),
            Encoding::Identity
        );
    }

    // --- Accept-Encoding parsing ---

    #[test]
    fn test_accept_encoding_with_quality_values() {
        // Quality values should not prevent matching
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("gzip;q=0.8, br;q=1.0")),
            Encoding::Brotli
        );
    }

    #[test]
    fn test_accept_encoding_wildcard() {
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("*")),
            Encoding::Zstd
        );
    }

    #[test]
    fn test_accept_encoding_with_spaces() {
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("  gzip , br ")),
            Encoding::Brotli
        );
    }

    // --- Encoding::as_str ---

    #[test]
    fn test_encoding_as_str() {
        assert_eq!(Encoding::Zstd.as_str(), "zstd");
        assert_eq!(Encoding::Brotli.as_str(), "br");
        assert_eq!(Encoding::Gzip.as_str(), "gzip");
        assert_eq!(Encoding::Identity.as_str(), "identity");
    }

    // --- Content-type exclusions ---

    #[test]
    fn test_should_compress_text_content_types() {
        assert!(should_compress_content_type(Some("text/html")));
        assert!(should_compress_content_type(Some(
            "text/plain; charset=utf-8"
        )));
        assert!(should_compress_content_type(Some("application/json")));
        assert!(should_compress_content_type(Some("application/javascript")));
        assert!(should_compress_content_type(Some("image/svg+xml")));
        assert!(should_compress_content_type(None));
    }

    #[test]
    fn test_should_skip_compressed_content_types() {
        assert!(!should_compress_content_type(Some("image/jpeg")));
        assert!(!should_compress_content_type(Some("image/png")));
        assert!(!should_compress_content_type(Some("video/mp4")));
        assert!(!should_compress_content_type(Some("audio/mpeg")));
        assert!(!should_compress_content_type(Some("application/zip")));
        assert!(!should_compress_content_type(Some("application/gzip")));
        assert!(!should_compress_content_type(Some("application/wasm")));
        assert!(!should_compress_content_type(Some("font/woff2")));
    }

    // --- compress_body ---

    #[test]
    fn test_compress_body_identity_passthrough() {
        let body = b"hello world";
        let out = compress_body(body, Encoding::Identity, None).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn test_compress_body_gzip_roundtrip() {
        use std::io::Read;
        let body: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let compressed = compress_body(&body, Encoding::Gzip, None).unwrap();
        assert_ne!(compressed, body, "compressed bytes should differ");
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn test_compress_body_brotli_roundtrip() {
        use std::io::Read;
        let body: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let compressed = compress_body(&body, Encoding::Brotli, None).unwrap();
        assert_ne!(compressed, body);
        let mut decoder = brotli::Decompressor::new(&compressed[..], 4096);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn test_compress_body_zstd_roundtrip() {
        let body: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let compressed = compress_body(&body, Encoding::Zstd, None).unwrap();
        assert_ne!(compressed, body);
        let decoded = zstd::decode_all(&compressed[..]).unwrap();
        assert_eq!(decoded, body);
    }

    // --- compression level ---

    /// A deterministic compressible payload with enough entropy that a
    /// higher effort setting finds strictly more savings than a lower one.
    /// Pure byte repetition compresses to the same handful of bytes at
    /// every level, which would make the ordering assertions vacuous.
    fn compressible_payload() -> Vec<u8> {
        const WORDS: [&str; 8] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
        ];
        let mut state: u64 = 0x5DEE_CE66_D511_ED15;
        let mut out = Vec::with_capacity(64 * 1024);
        while out.len() < 64 * 1024 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let word = WORDS[(state >> 33) as usize % WORDS.len()];
            out.extend_from_slice(word.as_bytes());
            out.push(b' ');
        }
        out
    }

    #[test]
    fn test_gzip_level_orders_output_size() {
        use std::io::Read;
        let body = compressible_payload();
        let fast = compress_body(&body, Encoding::Gzip, Some(1)).unwrap();
        let best = compress_body(&body, Encoding::Gzip, Some(9)).unwrap();
        assert!(
            best.len() < fast.len(),
            "gzip level 9 ({} bytes) must out-compress level 1 ({} bytes)",
            best.len(),
            fast.len()
        );
        let mut decoder = flate2::read::GzDecoder::new(&best[..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn test_brotli_level_orders_output_size() {
        use std::io::Read;
        let body = compressible_payload();
        let fast = compress_body(&body, Encoding::Brotli, Some(1)).unwrap();
        let best = compress_body(&body, Encoding::Brotli, Some(11)).unwrap();
        assert!(
            best.len() < fast.len(),
            "brotli quality 11 ({} bytes) must out-compress quality 1 ({} bytes)",
            best.len(),
            fast.len()
        );
        let mut decoder = brotli::Decompressor::new(&best[..], 4096);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn test_zstd_level_orders_output_size() {
        let body = compressible_payload();
        let fast = compress_body(&body, Encoding::Zstd, Some(1)).unwrap();
        let best = compress_body(&body, Encoding::Zstd, Some(19)).unwrap();
        assert!(
            best.len() < fast.len(),
            "zstd level 19 ({} bytes) must out-compress level 1 ({} bytes)",
            best.len(),
            fast.len()
        );
        let decoded = zstd::decode_all(&best[..]).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn test_out_of_range_level_clamps_instead_of_failing() {
        let body = compressible_payload();
        for encoding in [Encoding::Gzip, Encoding::Brotli, Encoding::Zstd] {
            let compressed = compress_body(&body, encoding, Some(999)).unwrap();
            assert!(
                !compressed.is_empty() && compressed.len() < body.len(),
                "{} must clamp an out-of-range level and still compress",
                encoding.as_str()
            );
        }
    }
}

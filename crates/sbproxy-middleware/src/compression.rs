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
/// Returns the original bytes unchanged for [`Encoding::Identity`]. The
/// gzip and zstd writers use their crates' default compression level; the
/// brotli encoder uses quality 4 (a balance between throughput and ratio
/// that matches what most reverse proxies ship by default).
pub fn compress_body(body: &[u8], encoding: Encoding) -> std::io::Result<Vec<u8>> {
    match encoding {
        Encoding::Identity => Ok(body.to_vec()),
        Encoding::Gzip => {
            let mut enc = flate2::write::GzEncoder::new(
                Vec::with_capacity(body.len()),
                flate2::Compression::default(),
            );
            enc.write_all(body)?;
            enc.finish()
        }
        Encoding::Brotli => {
            let mut out = Vec::with_capacity(body.len());
            let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 4, 22);
            writer.write_all(body)?;
            writer.flush()?;
            drop(writer);
            Ok(out)
        }
        Encoding::Zstd => zstd::encode_all(body, 0),
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
        let out = compress_body(body, Encoding::Identity).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn test_compress_body_gzip_roundtrip() {
        use std::io::Read;
        let body: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let compressed = compress_body(&body, Encoding::Gzip).unwrap();
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
        let compressed = compress_body(&body, Encoding::Brotli).unwrap();
        assert_ne!(compressed, body);
        let mut decoder = brotli::Decompressor::new(&compressed[..], 4096);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn test_compress_body_zstd_roundtrip() {
        let body: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let compressed = compress_body(&body, Encoding::Zstd).unwrap();
        assert_ne!(compressed, body);
        let decoded = zstd::decode_all(&compressed[..]).unwrap();
        assert_eq!(decoded, body);
    }
}

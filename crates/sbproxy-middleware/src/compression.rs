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

    /// Map a `compression.algorithms` token onto the codec it names.
    ///
    /// `None` for anything this proxy cannot produce. The config compiler
    /// refuses an unknown token at load (see
    /// `sbproxy_config::COMPRESSION_ALGORITHM_TOKENS`), so reaching `None`
    /// here means a caller built a `CompressionConfig` in code rather than
    /// from YAML.
    fn from_token(token: &str) -> Option<Encoding> {
        match token.trim().to_ascii_lowercase().as_str() {
            "zstd" => Some(Encoding::Zstd),
            "br" => Some(Encoding::Brotli),
            "gzip" => Some(Encoding::Gzip),
            _ => None,
        }
    }
}

/// Preference order used when `compression.algorithms` is empty: best
/// ratio first. A non-empty list is the operator's own order and is
/// walked as authored instead.
const DEFAULT_PREFERENCE: [Encoding; 3] = [Encoding::Zstd, Encoding::Brotli, Encoding::Gzip];

/// Select the response encoding from the `Accept-Encoding` header and the
/// origin's compression config.
///
/// `compression.algorithms` is a priority order, not a membership set: the
/// list is walked in declaration order and the first codec the client
/// accepts wins, so `algorithms: [gzip, br]` serves gzip to a client that
/// accepts both. An empty list means the operator expressed no preference
/// and falls back to the best-ratio-first ladder zstd > br > gzip.
///
/// Client qvalues are read as accept-or-refuse only, per RFC 9110 §12.5.3:
/// `q=0` is an explicit refusal of that coding and removes it from
/// consideration. A non-zero qvalue does not reorder the server-side
/// preference above, which RFC 9110 leaves to the server.
///
/// Returns [`Encoding::Identity`] when compression is disabled,
/// `accept_encoding` is absent, or the client accepts none of the
/// configured codecs.
pub fn negotiate_encoding(config: &CompressionConfig, accept_encoding: Option<&str>) -> Encoding {
    if !config.enabled {
        return Encoding::Identity;
    }

    let accept = match accept_encoding {
        Some(s) if !s.is_empty() => s,
        _ => return Encoding::Identity,
    };
    let acceptable = AcceptEncoding::parse(accept);

    if config.algorithms.is_empty() {
        return DEFAULT_PREFERENCE
            .into_iter()
            .find(|enc| acceptable.accepts(enc.as_str()))
            .unwrap_or(Encoding::Identity);
    }

    config
        .algorithms
        .iter()
        // A token naming no codec this proxy can produce is refused at
        // config load; skipping it here keeps a directly-constructed
        // config from disabling the codecs listed either side of it.
        .filter_map(|name| Encoding::from_token(name.as_str()))
        .find(|enc| acceptable.accepts(enc.as_str()))
        .unwrap_or(Encoding::Identity)
}

/// A parsed `Accept-Encoding` header.
///
/// The qvalue has to be read rather than trimmed off: RFC 9110 §12.5.3
/// gives `q=0` the meaning "not acceptable", so `gzip;q=0` is a refusal of
/// gzip and `identity;q=1, *;q=0` (the standard "send me nothing I did not
/// name" opt-out) refuses every coding the header does not list.
struct AcceptEncoding<'a> {
    /// `(coding, qvalue)` for every explicitly named coding, in header
    /// order. Codings are compared case-insensitively.
    codings: Vec<(&'a str, f32)>,
    /// qvalue attached to `*`, when the header carries one.
    wildcard: Option<f32>,
}

impl<'a> AcceptEncoding<'a> {
    fn parse(header: &'a str) -> Self {
        let mut codings = Vec::new();
        let mut wildcard = None;
        for element in header.split(',') {
            let mut parts = element.split(';');
            let coding = parts.next().unwrap_or("").trim();
            if coding.is_empty() {
                continue;
            }
            let mut q = 1.0f32;
            for param in parts {
                let param = param.trim();
                let Some(value) = param.split_once('=').and_then(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("q").then_some(value)
                }) else {
                    continue;
                };
                // An unparseable qvalue reads as the default 1.0 rather
                // than as a refusal: a malformed parameter must not
                // silently switch compression off for that client.
                q = value.trim().parse::<f32>().unwrap_or(1.0);
                break;
            }
            if coding == "*" {
                wildcard = Some(q);
            } else {
                codings.push((coding, q));
            }
        }
        Self { codings, wildcard }
    }

    /// Whether the client will accept `token`.
    ///
    /// An explicitly named coding decides on its own qvalue; `*` stands in
    /// only for codings the header does not name, which is what makes
    /// `identity;q=1, *;q=0` a refusal and `gzip, *;q=0` a gzip-only
    /// request.
    fn accepts(&self, token: &str) -> bool {
        if let Some((_, q)) = self
            .codings
            .iter()
            .find(|(coding, _)| coding.eq_ignore_ascii_case(token))
        {
            return *q > 0.0;
        }
        self.wildcard.is_some_and(|q| q > 0.0)
    }
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

    // --- Configured order is a priority order (H30) ---

    fn config_with(algorithms: &[&str]) -> CompressionConfig {
        CompressionConfig {
            enabled: true,
            algorithms: algorithms.iter().map(|a| (*a).to_string()).collect(),
            min_size: 0,
            level: None,
        }
    }

    #[test]
    fn configured_order_is_honoured_over_the_default_ladder() {
        // The operator's CDN caches gzip, so gzip is listed first. The
        // client accepts everything. Before the fix the list was a
        // membership set and the hardcoded zstd > br > gzip ladder picked
        // Brotli regardless of what the operator wrote.
        assert_eq!(
            negotiate_encoding(&config_with(&["gzip", "br"]), Some("gzip, br, zstd")),
            Encoding::Gzip
        );
        assert_eq!(
            negotiate_encoding(&config_with(&["gzip", "zstd"]), Some("gzip, br, zstd")),
            Encoding::Gzip
        );
        // Reversing the authored order reverses the selection, which is
        // what makes this a priority order rather than a set.
        assert_eq!(
            negotiate_encoding(&config_with(&["br", "gzip"]), Some("gzip, br, zstd")),
            Encoding::Brotli
        );
    }

    #[test]
    fn configured_order_falls_through_to_the_next_entry_the_client_accepts() {
        // First choice unacceptable to this client, second choice serves.
        assert_eq!(
            negotiate_encoding(&config_with(&["zstd", "gzip"]), Some("gzip")),
            Encoding::Gzip
        );
    }

    #[test]
    fn empty_algorithms_uses_the_best_ratio_ladder() {
        assert_eq!(
            negotiate_encoding(&config_with(&[]), Some("gzip, br, zstd")),
            Encoding::Zstd
        );
    }

    #[test]
    fn every_configured_token_maps_to_a_codec_and_back() {
        // The compiler refuses a token outside
        // `COMPRESSION_ALGORITHM_TOKENS`, so that list and this crate's
        // token mapping have to name the same codecs. Pinned here because
        // this is the only crate that can see both.
        for token in sbproxy_config::COMPRESSION_ALGORITHM_TOKENS {
            let encoding = Encoding::from_token(token)
                .unwrap_or_else(|| panic!("config accepts `{token}` but no codec produces it"));
            assert_eq!(encoding.as_str(), token);
        }
        for encoding in DEFAULT_PREFERENCE {
            assert!(
                sbproxy_config::COMPRESSION_ALGORITHM_TOKENS.contains(&encoding.as_str()),
                "{} is negotiable but the config compiler refuses the token",
                encoding.as_str()
            );
        }
    }

    // --- qvalues are refusals, not decoration (H33) ---

    #[test]
    fn q_zero_on_a_named_coding_is_a_refusal() {
        // RFC 9110 §12.5.3: `q=0` means "not acceptable". Before the fix
        // the parser trimmed at `;` and read this as plain `gzip`.
        assert_eq!(
            negotiate_encoding(&config_with(&["gzip"]), Some("gzip;q=0")),
            Encoding::Identity
        );
        // The refusal is per coding: br is still on the table.
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("gzip;q=0, br")),
            Encoding::Brotli
        );
    }

    #[test]
    fn wildcard_q_zero_refuses_everything_not_named() {
        // The standard opt-out a client that can decode nothing sends.
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("identity;q=1, *;q=0")),
            Encoding::Identity
        );
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("*;q=0")),
            Encoding::Identity
        );
    }

    #[test]
    fn a_named_coding_outranks_the_wildcard() {
        // `*` stands in only for codings the header does not name, so an
        // explicit `gzip` survives a `*;q=0` and zstd does not.
        assert_eq!(
            negotiate_encoding(&enabled_config(), Some("gzip, *;q=0")),
            Encoding::Gzip
        );
        // And the inverse: a named refusal is not undone by a permissive
        // wildcard.
        assert_eq!(
            negotiate_encoding(&config_with(&["zstd"]), Some("zstd;q=0, *")),
            Encoding::Identity
        );
    }

    #[test]
    fn a_nonzero_qvalue_still_accepts() {
        assert_eq!(
            negotiate_encoding(&config_with(&["gzip"]), Some("gzip;q=0.001")),
            Encoding::Gzip
        );
        // A malformed qvalue must not read as a refusal.
        assert_eq!(
            negotiate_encoding(&config_with(&["gzip"]), Some("gzip;q=banana")),
            Encoding::Gzip
        );
        // Parameter names are case-insensitive.
        assert_eq!(
            negotiate_encoding(&config_with(&["gzip"]), Some("gzip;Q=0")),
            Encoding::Identity
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

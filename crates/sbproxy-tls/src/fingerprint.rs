//! TLS ClientHello fingerprinting (JA3 / JA4 / JA4H / JA4S).
//!
//! Wave 5 / G5.3. See `docs/adr-tls-fingerprint-pipeline.md` (A5.1)
//! for the full contract.
//!
//! # What this module produces
//!
//! - **JA3** (Salesforce 2017): MD5 of the comma-delimited TLS 1.2
//!   ClientHello fields (version, ciphers, extensions, EC curves, EC
//!   point formats), with GREASE values (RFC 8701) filtered before
//!   hashing for stability across library patch releases.
//! - **JA4** (FoxIO 2023): structured 10-character prefix joined by
//!   `_` to a 12-character truncated SHA-256 of the sorted cipher
//!   suite list. Spec: <https://github.com/FoxIO-LLC/ja4>.
//! - **JA4H** (HTTP request fingerprint): computed mid-pipeline by
//!   `sbproxy-core` once headers are read; this module exports the
//!   pure helper so the request pipeline can call it without a TLS
//!   crate dep.
//! - **JA4S** (ServerHello): outbound fingerprint of the upstream's
//!   reply. Stub here. Wave 5 leaves the field as `None`; outbound
//!   capture lands with the connector hardening in B5.x.
//!
//! # Capture point
//!
//! The pure parser in [`parse_client_hello`] is invoked from a
//! Pingora TLS session lifecycle hook after the ClientHello is read.
//! The Pingora glue is intentionally thin (just the hook adapter); all
//! of the parsing logic lives here so it can be unit-tested without a
//! real handshake.
//!
//! # Feature gating
//!
//! Behind the `tls-fingerprint` cargo feature (default off). When the
//! feature is disabled, the type definitions still exist (so
//! `RequestContext::tls_fingerprint: Option<TlsFingerprint>` compiles
//! either way) but none of the parsing paths run. Per A5.1 the
//! capture cost is 50-100 microseconds per handshake on a typical
//! 300-500 byte ClientHello.

use std::net::IpAddr;

// --- Public types ---

/// TLS fingerprint bundle attached to a `RequestContext`.
///
/// Fields are independently optional because they are populated at
/// different points in the pipeline:
///
/// - [`Self::ja3`] / [`Self::ja4`] are populated by
///   [`parse_client_hello`] at TLS handshake time.
/// - [`Self::ja4h`] is populated mid-pipeline by [`compute_ja4h`]
///   once the request headers are available.
/// - [`Self::ja4s`] is populated on the outbound TLS session to the
///   upstream (Wave 5 leaves it `None`; outbound lands with B5.x).
/// - [`Self::trustworthy`] is computed from the per-origin CIDR
///   config in `sb.yml` by [`classify_trustworthy`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct TlsFingerprint {
    /// JA3 fingerprint: 32-character lowercase hex MD5 of the JA3
    /// input string. `None` when the ClientHello could not be parsed.
    pub ja3: Option<String>,
    /// JA4 fingerprint: structured 10-character prefix + `_` +
    /// 12-character truncated SHA-256 of the sorted cipher suite
    /// list. Example: `"t13d1516h2_8daaf6152771"`. `None` when the
    /// ClientHello could not be parsed.
    pub ja4: Option<String>,
    /// JA4H HTTP request fingerprint: 12-character truncated SHA-256
    /// of the ordered request header names. Populated mid-pipeline,
    /// not at handshake time.
    pub ja4h: Option<String>,
    /// JA4S TLS ServerHello fingerprint from the proxy's outbound
    /// session. Populated by the upstream connector. `None` for
    /// inbound-only captures.
    pub ja4s: Option<String>,
    /// Whether the fingerprint reflects the actual client rather
    /// than an intermediate proxy / CDN. Computed from per-origin
    /// CIDR rules; defaults to `false` when no rule matches
    /// (conservative, per A5.1).
    pub trustworthy: bool,
}

impl TlsFingerprint {
    /// Empty fingerprint with all fields `None` and
    /// `trustworthy = false`. Equivalent to the type's `Default` but
    /// spelled out for readability at callsites.
    pub fn empty() -> Self {
        Self::default()
    }
}

// --- ClientHello parser ---

/// TLS record-layer constants. These are the bytes a TLS handshake
/// record carries on the wire; we parse the ClientHello structure
/// from a raw byte slice.
const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Parse a raw ClientHello byte slice and compute the JA3 + JA4
/// fingerprints.
///
/// The input is expected to be either:
///
/// - A full TLS record starting with `0x16 03 0X LL LL ...` (a
///   handshake record carrying the ClientHello), or
/// - The ClientHello body itself starting with `0x01 LL LL LL ...`.
///
/// Both shapes occur in practice depending on which Pingora hook
/// surfaces the bytes. The parser auto-detects.
///
/// Returns a [`TlsFingerprint`] with `ja3` and `ja4` populated on
/// success. `ja4h` and `ja4s` stay `None` (those are filled later in
/// the pipeline). `trustworthy` defaults to `false`; callers should
/// run [`classify_trustworthy`] against the request's client IP and
/// the per-origin config.
///
/// On parse failure the returned [`TlsFingerprint`] has all hash
/// fields `None`. Failure does not panic and does not log; the
/// caller can choose whether to record a metric.
pub fn parse_client_hello(bytes: &[u8]) -> TlsFingerprint {
    let body = match strip_record_header(bytes) {
        Some(b) => b,
        None => return TlsFingerprint::empty(),
    };

    let parsed = match parse_client_hello_body(body) {
        Some(p) => p,
        None => return TlsFingerprint::empty(),
    };

    let ja3 = compute_ja3(&parsed);
    let ja4 = compute_ja4(&parsed);

    TlsFingerprint {
        ja3: Some(ja3),
        ja4: Some(ja4),
        ja4h: None,
        ja4s: None,
        trustworthy: false,
    }
}

/// Detect whether `bytes` begins with a full TLS record header.
///
/// Returns the body slice (everything after the 5-byte record header
/// plus the 4-byte handshake header), or treats the input as an
/// already-stripped ClientHello body.
fn strip_record_header(bytes: &[u8]) -> Option<&[u8]> {
    // Shape A: full TLS record.
    // 0: 0x16 (handshake)
    // 1-2: TLS legacy version (0x03 0xXX)
    // 3-4: record length (big-endian)
    // 5: 0x01 (ClientHello)
    // 6-8: handshake length (3 bytes, big-endian)
    // 9..: ClientHello body
    if bytes.len() >= 9
        && bytes[0] == TLS_HANDSHAKE_RECORD
        && bytes[5] == TLS_HANDSHAKE_CLIENT_HELLO
    {
        return Some(&bytes[9..]);
    }
    // Shape B: handshake-only.
    // 0: 0x01 (ClientHello)
    // 1-3: handshake length
    // 4..: ClientHello body
    if bytes.len() >= 4 && bytes[0] == TLS_HANDSHAKE_CLIENT_HELLO {
        return Some(&bytes[4..]);
    }
    // Shape C: already-stripped body. Fall through.
    Some(bytes)
}

/// Result of parsing a ClientHello body.
#[derive(Debug, Clone)]
struct ParsedClientHello {
    /// `legacy_version` field. For TLS 1.3 this is always `0x0303`
    /// (TLS 1.2) per RFC 8446 §4.1.2; the real version is in the
    /// `supported_versions` extension.
    legacy_version: u16,
    /// Cipher suites in declaration order, GREASE filtered.
    ciphers: Vec<u16>,
    /// Extensions in declaration order, GREASE filtered.
    extensions: Vec<u16>,
    /// EC named groups (extension 0x000a), GREASE filtered.
    curves: Vec<u16>,
    /// EC point formats (extension 0x000b).
    ec_point_formats: Vec<u8>,
    /// Negotiated TLS version from `supported_versions` (extension
    /// 0x002b). Highest non-GREASE version wins.
    supported_version: Option<u16>,
    /// SNI present? (extension 0x0000).
    has_sni: bool,
    /// First and last ALPN values (extension 0x0010), GREASE
    /// filtered. Each entry is the ALPN protocol ID string.
    alpn_first: Option<String>,
    alpn_last: Option<String>,
    /// Signature algorithms (extension 0x000d), GREASE filtered.
    /// Not currently consumed by JA3 / JA4 emission, but parsed
    /// here so the JA4-extended (`ja4_r`) variant can be added in a
    /// follow-up without re-walking the wire bytes.
    #[allow(dead_code)]
    sig_algs: Vec<u16>,
}

fn parse_client_hello_body(body: &[u8]) -> Option<ParsedClientHello> {
    let mut p = ByteReader::new(body);

    // legacy_version (2) + random (32) + session_id_len (1) + session_id.
    let legacy_version = p.read_u16()?;
    p.skip(32)?;
    let session_id_len = p.read_u8()? as usize;
    p.skip(session_id_len)?;

    // cipher_suites
    let cipher_bytes = p.read_u16()? as usize;
    if !cipher_bytes.is_multiple_of(2) {
        return None;
    }
    let mut ciphers = Vec::with_capacity(cipher_bytes / 2);
    for _ in 0..(cipher_bytes / 2) {
        let c = p.read_u16()?;
        if !is_grease(c) {
            ciphers.push(c);
        }
    }

    // compression_methods
    let comp_len = p.read_u8()? as usize;
    p.skip(comp_len)?;

    // extensions
    let ext_total = p.read_u16()? as usize;
    let mut ext_reader = ByteReader::new(p.take(ext_total)?);

    let mut extensions = Vec::new();
    let mut curves = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut supported_version: Option<u16> = None;
    let mut has_sni = false;
    let mut alpn_first: Option<String> = None;
    let mut alpn_last: Option<String> = None;
    let mut sig_algs = Vec::new();

    while ext_reader.remaining() >= 4 {
        let ext_type = ext_reader.read_u16()?;
        let ext_len = ext_reader.read_u16()? as usize;
        let ext_data = ext_reader.take(ext_len)?;

        if is_grease(ext_type) {
            continue;
        }
        extensions.push(ext_type);

        match ext_type {
            // server_name
            0x0000 => {
                has_sni = true;
            }
            // supported_groups (named curves)
            0x000a => {
                let mut r = ByteReader::new(ext_data);
                let list_len = r.read_u16()? as usize;
                if list_len.is_multiple_of(2) {
                    for _ in 0..(list_len / 2) {
                        let g = r.read_u16()?;
                        if !is_grease(g) {
                            curves.push(g);
                        }
                    }
                }
            }
            // ec_point_formats
            0x000b => {
                let mut r = ByteReader::new(ext_data);
                let list_len = r.read_u8()? as usize;
                for _ in 0..list_len {
                    ec_point_formats.push(r.read_u8()?);
                }
            }
            // signature_algorithms
            0x000d => {
                let mut r = ByteReader::new(ext_data);
                let list_len = r.read_u16()? as usize;
                if list_len.is_multiple_of(2) {
                    for _ in 0..(list_len / 2) {
                        let s = r.read_u16()?;
                        if !is_grease(s) {
                            sig_algs.push(s);
                        }
                    }
                }
            }
            // application_layer_protocol_negotiation (ALPN)
            0x0010 => {
                let mut r = ByteReader::new(ext_data);
                let list_len = r.read_u16()? as usize;
                let mut alpn_data = ByteReader::new(r.take(list_len)?);
                let mut all_alpns: Vec<String> = Vec::new();
                while alpn_data.remaining() > 0 {
                    let proto_len = alpn_data.read_u8()? as usize;
                    let proto_bytes = alpn_data.take(proto_len)?;
                    let s = String::from_utf8_lossy(proto_bytes).into_owned();
                    if !s.is_empty() {
                        all_alpns.push(s);
                    }
                }
                alpn_first = all_alpns.first().cloned();
                alpn_last = all_alpns.last().cloned();
            }
            // supported_versions
            0x002b => {
                let mut r = ByteReader::new(ext_data);
                let list_len = r.read_u8()? as usize;
                if list_len.is_multiple_of(2) {
                    let mut highest: Option<u16> = None;
                    for _ in 0..(list_len / 2) {
                        let v = r.read_u16()?;
                        if is_grease(v) {
                            continue;
                        }
                        highest = Some(match highest {
                            Some(h) => h.max(v),
                            None => v,
                        });
                    }
                    supported_version = highest;
                }
            }
            _ => {}
        }
    }

    Some(ParsedClientHello {
        legacy_version,
        ciphers,
        extensions,
        curves,
        ec_point_formats,
        supported_version,
        has_sni,
        alpn_first,
        alpn_last,
        sig_algs,
    })
}

// --- JA3 ---

fn compute_ja3(p: &ParsedClientHello) -> String {
    use md5::{Digest as _, Md5};

    let version = p.legacy_version;
    let join_u16 = |xs: &[u16]| xs.iter().map(u16::to_string).collect::<Vec<_>>().join("-");
    let join_u8 = |xs: &[u8]| xs.iter().map(u8::to_string).collect::<Vec<_>>().join("-");

    let input = format!(
        "{},{},{},{},{}",
        version,
        join_u16(&p.ciphers),
        join_u16(&p.extensions),
        join_u16(&p.curves),
        join_u8(&p.ec_point_formats),
    );
    let digest = Md5::digest(input.as_bytes());
    hex::encode(digest)
}

// --- JA4 ---

fn compute_ja4(p: &ParsedClientHello) -> String {
    // Section A: 10-character structured prefix.
    //
    // Format per FoxIO spec (https://github.com/FoxIO-LLC/ja4):
    //   <protocol><tls_version><sni_indicator><cipher_count><extension_count><alpn_first><alpn_last>
    //
    // - protocol: 't' (TLS over TCP) or 'q' (QUIC). Wave 5 captures
    //   inbound TCP TLS only; QUIC captures land with the H3
    //   listener hook. We hard-code 't' here.
    // - tls_version: 2 ASCII digits encoding the negotiated TLS
    //   version. TLS 1.3 -> "13", TLS 1.2 -> "12", TLS 1.1 -> "11",
    //   TLS 1.0 -> "10".
    // - sni_indicator: 'd' if SNI extension present, 'i' otherwise.
    // - cipher_count: 2-digit zero-padded count of GREASE-filtered
    //   ciphers, capped at 99.
    // - extension_count: 2-digit zero-padded count of GREASE-filtered
    //   extensions, capped at 99.
    // - alpn_first / alpn_last: first ASCII char of the first / last
    //   ALPN value, or '0' when absent. The FoxIO spec uses two
    //   chars; we follow the published implementation that uses the
    //   first byte of each value.
    let proto = 't';
    let version_str = ja4_version_chars(p.supported_version.unwrap_or(p.legacy_version));
    let sni = if p.has_sni { 'd' } else { 'i' };
    let cipher_count = format!("{:02}", p.ciphers.len().min(99));
    let ext_count = format!("{:02}", p.extensions.len().min(99));

    let alpn_first_byte = first_char_or_zero(p.alpn_first.as_deref());
    let alpn_last_byte = first_char_or_zero(p.alpn_last.as_deref());

    let mut prefix = String::with_capacity(10);
    prefix.push(proto);
    prefix.push_str(&version_str);
    prefix.push(sni);
    prefix.push_str(&cipher_count);
    prefix.push_str(&ext_count);
    prefix.push(alpn_first_byte);
    prefix.push(alpn_last_byte);

    // Section B: 12-character truncated SHA-256 of the sorted cipher
    // suite list (hex strings, comma-delimited). Sorting makes the
    // hash stable across libraries that order ciphers differently.
    let cipher_b = ja4_cipher_hash(&p.ciphers);

    format!("{prefix}_{cipher_b}")
}

fn ja4_version_chars(ver: u16) -> String {
    match ver {
        0x0304 => "13".to_string(),
        0x0303 => "12".to_string(),
        0x0302 => "11".to_string(),
        0x0301 => "10".to_string(),
        _ => "00".to_string(),
    }
}

fn first_char_or_zero(s: Option<&str>) -> char {
    match s.and_then(|v| v.bytes().next()) {
        Some(b) if b.is_ascii_alphanumeric() => b as char,
        _ => '0',
    }
}

fn ja4_cipher_hash(ciphers: &[u16]) -> String {
    use sha2::{Digest as _, Sha256};

    let mut sorted: Vec<u16> = ciphers.to_vec();
    sorted.sort_unstable();
    let joined: String = sorted
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let digest = Sha256::digest(joined.as_bytes());
    let hex_full = hex::encode(digest);
    hex_full.chars().take(12).collect()
}

// --- JA4H (HTTP fingerprint) ---

/// Compute the JA4H fingerprint from request method + version +
/// ordered header names.
///
/// Per A5.1: "the input is the ordered list of request header names
/// (values excluded) concatenated with a method-and-version prefix.
/// The hash is a 12-character truncated SHA-256."
///
/// `method` is the HTTP method string (e.g. `"GET"`).
/// `version` is the HTTP version label (`"1.1"`, `"2"`, `"3"`).
/// `headers` is the iterator of header names in the order they
/// appeared on the wire. Names are normalised to lowercase before
/// hashing so HTTP/2-style lowercase headers and HTTP/1.1-style
/// canonical headers produce the same fingerprint.
pub fn compute_ja4h<'a, I>(method: &str, version: &str, headers: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    use sha2::{Digest as _, Sha256};

    let mut input = String::new();
    input.push_str(method);
    input.push('|');
    input.push_str(version);
    input.push('|');
    let names: Vec<String> = headers
        .into_iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    input.push_str(&names.join(","));

    let digest = Sha256::digest(input.as_bytes());
    let hex_full = hex::encode(digest);
    hex_full.chars().take(12).collect()
}

// --- Trustworthy classifier ---

/// CIDR config governing whether a fingerprint is trustworthy.
///
/// Operators populate this from the per-origin
/// `features.tls_fingerprint.{trustworthy,untrusted}_client_cidrs`
/// blocks in `sb.yml`. The lists are evaluated in order:
///
/// 1. If `client_ip` matches any entry in `untrusted`, return
///    `false`.
/// 2. Else if `client_ip` matches any entry in `trustworthy`, return
///    `true`.
/// 3. Else default to `false` (conservative, per A5.1).
#[derive(Debug, Clone, Default)]
pub struct TrustworthyConfig {
    /// CIDR ranges where direct clients arrive (no CDN / MITM).
    pub trustworthy: Vec<ipnetwork::IpNetwork>,
    /// CIDR ranges known to terminate TLS upstream of the proxy
    /// (CDN egress, corporate MITM, VPN).
    pub untrusted: Vec<ipnetwork::IpNetwork>,
}

impl TrustworthyConfig {
    /// Build a [`TrustworthyConfig`] from string CIDR lists.
    /// Invalid entries are skipped with a `tracing::warn!`.
    pub fn from_strings(trustworthy: &[String], untrusted: &[String]) -> Self {
        let trustworthy = trustworthy
            .iter()
            .filter_map(|s| match s.parse::<ipnetwork::IpNetwork>() {
                Ok(n) => Some(n),
                Err(e) => {
                    tracing::warn!(
                        cidr = %s,
                        error = %e,
                        "skipping invalid trustworthy_client_cidrs entry"
                    );
                    None
                }
            })
            .collect();
        let untrusted = untrusted
            .iter()
            .filter_map(|s| match s.parse::<ipnetwork::IpNetwork>() {
                Ok(n) => Some(n),
                Err(e) => {
                    tracing::warn!(
                        cidr = %s,
                        error = %e,
                        "skipping invalid untrusted_client_cidrs entry"
                    );
                    None
                }
            })
            .collect();
        Self {
            trustworthy,
            untrusted,
        }
    }
}

/// Resolve the trustworthy flag for a given client IP against the
/// per-origin CIDR rules.
///
/// Default is `false` (conservative) when `client_ip` is `None` or
/// no rule matches. See [`TrustworthyConfig`] for the matching
/// order.
pub fn classify_trustworthy(cfg: &TrustworthyConfig, client_ip: Option<IpAddr>) -> bool {
    let ip = match client_ip {
        Some(ip) => ip,
        None => return false,
    };
    if cfg.untrusted.iter().any(|n| n.contains(ip)) {
        return false;
    }
    if cfg.trustworthy.iter().any(|n| n.contains(ip)) {
        return true;
    }
    false
}

// --- GREASE filtering (RFC 8701) ---

/// RFC 8701 reserves cipher / extension / version values of the
/// shape `0x[0-F]A0x[0-F]A` (lower nibble of each byte equals A) as
/// GREASE markers that clients deliberately rotate. JA3 and JA4
/// both filter GREASE before hashing for stability across library
/// patch releases.
fn is_grease(value: u16) -> bool {
    let lo = (value & 0xff) as u8;
    let hi = (value >> 8) as u8;
    // Both bytes must equal 0xNA where N==N (the FoxIO + Salesforce
    // canonical form is 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA).
    lo == hi && (lo & 0x0f) == 0x0a
}

// --- Internal byte reader ---

/// Minimal big-endian byte reader for the ClientHello parser.
/// Returns `None` on short read so the caller can short-circuit
/// without panicking on malformed input.
struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn read_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.buf.len() {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        self.pos += n;
        Some(())
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid TLS 1.3 ClientHello body covering the
    /// fields the parser reads. Returns just the body (no record
    /// header). Useful for round-trip parsing tests without depending
    /// on a real handshake.
    fn synthetic_client_hello() -> Vec<u8> {
        let mut b = Vec::new();
        // legacy_version
        b.extend_from_slice(&[0x03, 0x03]);
        // random
        b.extend_from_slice(&[0u8; 32]);
        // session_id (empty)
        b.push(0);
        // cipher_suites: [GREASE, 0x1301 (TLS_AES_128_GCM_SHA256), 0x1302]
        b.extend_from_slice(&[0x00, 0x06]); // 6 bytes -> 3 ciphers
        b.extend_from_slice(&[0x0a, 0x0a]); // GREASE
        b.extend_from_slice(&[0x13, 0x01]);
        b.extend_from_slice(&[0x13, 0x02]);
        // compression_methods: [0]
        b.extend_from_slice(&[0x01, 0x00]);

        // --- Extensions ---
        let mut ext = Vec::new();

        // server_name (0x0000), payload size 1 byte just so it parses.
        ext.extend_from_slice(&[0x00, 0x00]); // type
        ext.extend_from_slice(&[0x00, 0x00]); // length 0

        // supported_groups (0x000a): list of [GREASE, 0x001d (X25519)]
        ext.extend_from_slice(&[0x00, 0x0a]);
        ext.extend_from_slice(&[0x00, 0x06]); // ext length
        ext.extend_from_slice(&[0x00, 0x04]); // list length
        ext.extend_from_slice(&[0x0a, 0x0a]); // GREASE curve
        ext.extend_from_slice(&[0x00, 0x1d]); // X25519

        // ec_point_formats (0x000b): [0]
        ext.extend_from_slice(&[0x00, 0x0b]);
        ext.extend_from_slice(&[0x00, 0x02]); // ext length
        ext.extend_from_slice(&[0x01, 0x00]); // 1 entry, value 0

        // ALPN (0x0010): ["h2", "http/1.1"]
        let mut alpn = Vec::new();
        alpn.push(2u8);
        alpn.extend_from_slice(b"h2");
        alpn.push(8u8);
        alpn.extend_from_slice(b"http/1.1");
        let alpn_list_len = alpn.len() as u16;
        let alpn_ext_len = alpn_list_len + 2;
        ext.extend_from_slice(&[0x00, 0x10]);
        ext.extend_from_slice(&alpn_ext_len.to_be_bytes());
        ext.extend_from_slice(&alpn_list_len.to_be_bytes());
        ext.extend_from_slice(&alpn);

        // supported_versions (0x002b): [GREASE, 0x0304 (TLS 1.3)]
        ext.extend_from_slice(&[0x00, 0x2b]);
        ext.extend_from_slice(&[0x00, 0x05]); // ext length
        ext.extend_from_slice(&[0x04]); // list length (4 bytes)
        ext.extend_from_slice(&[0x0a, 0x0a]); // GREASE
        ext.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

        let ext_len = ext.len() as u16;
        b.extend_from_slice(&ext_len.to_be_bytes());
        b.extend_from_slice(&ext);
        b
    }

    #[test]
    fn parses_synthetic_client_hello_and_filters_grease() {
        let body = synthetic_client_hello();
        let parsed = parse_client_hello_body(&body).expect("parse");
        // GREASE 0x0a0a stripped, leaving the two real ciphers.
        assert_eq!(parsed.ciphers, vec![0x1301, 0x1302]);
        // GREASE curve stripped, X25519 left.
        assert_eq!(parsed.curves, vec![0x001d]);
        // EC point formats parsed.
        assert_eq!(parsed.ec_point_formats, vec![0]);
        // Extensions GREASE-filtered (synthetic hello had no GREASE
        // extension entries; just the four real ones).
        assert!(parsed.extensions.contains(&0x0000)); // SNI
        assert!(parsed.extensions.contains(&0x000a)); // groups
        assert!(parsed.extensions.contains(&0x002b)); // supported_versions
        assert!(parsed.has_sni);
        assert_eq!(parsed.supported_version, Some(0x0304));
        assert_eq!(parsed.alpn_first.as_deref(), Some("h2"));
        assert_eq!(parsed.alpn_last.as_deref(), Some("http/1.1"));
    }

    #[test]
    fn ja3_format_is_md5_hex_32_chars() {
        let body = synthetic_client_hello();
        let fp = parse_client_hello(&body);
        let ja3 = fp.ja3.expect("ja3 populated");
        assert_eq!(ja3.len(), 32);
        assert!(ja3.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable hash for the synthetic ClientHello: regression-pin it
        // so future refactors of the JA3 input string surface as a
        // failing test rather than silent drift. Recomputed by
        // running this module's parser, captured 2026-05-01.
        assert_eq!(ja3, "773a820ef18383c8533e03ddcebf348b");
    }

    #[test]
    fn ja3_grease_filtering_is_stable() {
        // Two ClientHellos that differ only in GREASE values produce
        // the same JA3. This is the headline stability property of
        // RFC 8701 + Salesforce's JA3 spec.
        let mut body_a = synthetic_client_hello();
        let mut body_b = synthetic_client_hello();
        // Mutate the GREASE cipher byte: 0x0a0a -> 0x1a1a. Both are
        // GREASE values per RFC 8701.
        // The cipher list starts at: 2 (legacy_ver) + 32 (random) + 1
        // (session_id_len) + 2 (cipher_bytes_len) = 37.
        body_a[37] = 0x0a;
        body_a[38] = 0x0a;
        body_b[37] = 0x1a;
        body_b[38] = 0x1a;
        let a = parse_client_hello(&body_a).ja3.unwrap();
        let b = parse_client_hello(&body_b).ja3.unwrap();
        assert_eq!(a, b, "GREASE rotation must not change JA3");
    }

    #[test]
    fn ja4_prefix_structure_is_correct() {
        let body = synthetic_client_hello();
        let fp = parse_client_hello(&body);
        let ja4 = fp.ja4.expect("ja4 populated");
        // Format: 10-char prefix + '_' + 12-char hash.
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 2, "JA4 has exactly one underscore");
        assert_eq!(parts[0].len(), 10, "JA4 prefix is exactly 10 chars: {ja4}");
        assert_eq!(parts[1].len(), 12, "JA4 hash is exactly 12 chars: {ja4}");
        // Protocol char.
        assert_eq!(&parts[0][0..1], "t");
        // TLS 1.3 negotiated via supported_versions.
        assert_eq!(&parts[0][1..3], "13");
        // SNI present in the synthetic hello.
        assert_eq!(&parts[0][3..4], "d");
        // 2 ciphers after GREASE filtering. Synthetic hello has 5
        // extensions: SNI, supported_groups, ec_point_formats, ALPN,
        // supported_versions.
        assert_eq!(&parts[0][4..6], "02");
        assert_eq!(&parts[0][6..8], "05");
        // ALPN first/last bytes: 'h' + 'h' (h2 / http/1.1).
        assert_eq!(&parts[0][8..10], "hh");
    }

    #[test]
    fn ja4_cipher_hash_is_sort_stable() {
        // Two cipher orderings produce the same JA4 hash because JA4
        // sorts before hashing.
        let h1 = ja4_cipher_hash(&[0x1302, 0x1301]);
        let h2 = ja4_cipher_hash(&[0x1301, 0x1302]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 12);
    }

    #[test]
    fn ja4h_method_and_header_order_changes_hash() {
        let h_get = compute_ja4h("GET", "1.1", ["host", "user-agent", "accept"]);
        let h_post = compute_ja4h("POST", "1.1", ["host", "user-agent", "accept"]);
        let h_reordered = compute_ja4h("GET", "1.1", ["user-agent", "host", "accept"]);
        assert_ne!(h_get, h_post, "method change must alter ja4h");
        assert_ne!(h_get, h_reordered, "header order change must alter ja4h");
        assert_eq!(h_get.len(), 12);
    }

    #[test]
    fn ja4h_normalises_header_case() {
        let lower = compute_ja4h("GET", "1.1", ["host", "user-agent"]);
        let mixed = compute_ja4h("GET", "1.1", ["Host", "User-Agent"]);
        assert_eq!(
            lower, mixed,
            "ja4h must lowercase header names so HTTP/1.1 and HTTP/2 produce the same fingerprint"
        );
    }

    #[test]
    fn parse_client_hello_returns_empty_on_short_input() {
        let fp = parse_client_hello(&[]);
        assert!(fp.ja3.is_none());
        assert!(fp.ja4.is_none());
        let fp2 = parse_client_hello(&[0x16, 0x03, 0x03]);
        assert!(fp2.ja3.is_none());
    }

    #[test]
    fn parse_client_hello_accepts_full_record_header() {
        let body = synthetic_client_hello();
        // Wrap the body in a TLS record: 0x16 0x03 0x03 LL LL 0x01 LL LL LL <body>.
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        let body_with_hdr_len = (body.len() + 4) as u16;
        record.extend_from_slice(&body_with_hdr_len.to_be_bytes());
        record.push(0x01);
        let body_len = body.len() as u32;
        record.push(((body_len >> 16) & 0xff) as u8);
        record.push(((body_len >> 8) & 0xff) as u8);
        record.push((body_len & 0xff) as u8);
        record.extend_from_slice(&body);
        let fp = parse_client_hello(&record);
        assert!(fp.ja3.is_some(), "record-wrapped hello must parse");
        assert!(fp.ja4.is_some());
    }

    #[test]
    fn classify_trustworthy_default_is_false() {
        let cfg = TrustworthyConfig::default();
        assert!(!classify_trustworthy(&cfg, None));
        assert!(!classify_trustworthy(
            &cfg,
            Some("203.0.113.10".parse().unwrap())
        ));
    }

    #[test]
    fn classify_trustworthy_matches_explicit_cidr() {
        let cfg = TrustworthyConfig::from_strings(&["203.0.113.0/24".to_string()], &[]);
        assert!(classify_trustworthy(
            &cfg,
            Some("203.0.113.10".parse().unwrap())
        ));
        assert!(!classify_trustworthy(
            &cfg,
            Some("198.51.100.10".parse().unwrap())
        ));
    }

    #[test]
    fn classify_trustworthy_untrusted_overrides_trustworthy() {
        // An IP listed in BOTH trustworthy and untrusted resolves to
        // false because untrusted is checked first (conservative).
        let cfg = TrustworthyConfig::from_strings(
            &["203.0.113.0/24".to_string()],
            &["203.0.113.10/32".to_string()],
        );
        assert!(!classify_trustworthy(
            &cfg,
            Some("203.0.113.10".parse().unwrap())
        ));
        // Other IPs in the trustworthy block stay trustworthy.
        assert!(classify_trustworthy(
            &cfg,
            Some("203.0.113.11".parse().unwrap())
        ));
    }

    #[test]
    fn classify_trustworthy_handles_ipv6() {
        let cfg = TrustworthyConfig::from_strings(&["2001:db8::/32".to_string()], &[]);
        assert!(classify_trustworthy(
            &cfg,
            Some("2001:db8::1".parse().unwrap())
        ));
    }

    #[test]
    fn trustworthy_config_skips_invalid_cidrs() {
        let cfg =
            TrustworthyConfig::from_strings(&["bogus".to_string(), "10.0.0.0/8".to_string()], &[]);
        assert_eq!(cfg.trustworthy.len(), 1);
    }

    #[test]
    fn is_grease_recognises_canonical_values() {
        // RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ..., 0xfafa.
        // Both bytes equal `0xN A` with the same N; the lower nibble
        // is always 'A'.
        let canonical: [u16; 16] = [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
            0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ];
        for g in canonical {
            assert!(is_grease(g), "{:04x} should be GREASE", g);
        }
        assert!(!is_grease(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!is_grease(0x002f)); // a real legacy cipher
                                     // Non-canonical (mismatched bytes) MUST NOT be GREASE.
        assert!(!is_grease(0x1b0a));
    }

    #[test]
    fn ja4_falls_back_to_legacy_version_when_supported_versions_missing() {
        // Hand-roll a ClientHello with no supported_versions extension
        // so the parser falls back to legacy_version. Same shape as
        // synthetic_client_hello but without ext 0x002b.
        let mut b = Vec::new();
        b.extend_from_slice(&[0x03, 0x03]); // legacy_version: TLS 1.2
        b.extend_from_slice(&[0u8; 32]);
        b.push(0); // session_id len
        b.extend_from_slice(&[0x00, 0x02]); // cipher_bytes len
        b.extend_from_slice(&[0x13, 0x01]);
        b.extend_from_slice(&[0x01, 0x00]); // comp methods
        b.extend_from_slice(&[0x00, 0x04]); // ext total
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // SNI ext, len 0
        let fp = parse_client_hello(&b);
        let ja4 = fp.ja4.expect("ja4 populated");
        assert!(ja4.starts_with("t12"), "expected TLS 1.2 prefix in {ja4}");
    }
}

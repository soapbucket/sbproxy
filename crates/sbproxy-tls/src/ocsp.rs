//! OCSP response fetching and stapling.
//!
//! Fetches OCSP responses from the CA's OCSP responder URL (extracted from
//! the certificate's Authority Information Access extension) and caches them
//! for stapling during TLS handshakes. A background task refreshes the response
//! every 12 hours.
//!
//! # Scope of what gets stapled
//!
//! One certificate: the manual fallback loaded from `proxy.tls_cert_file`.
//! [`crate::TlsState::start_ocsp_refresh_task`] starts a refresh task only
//! when that file pair is configured, and its `on_update` callback writes
//! [`crate::cert_resolver::CertResolver::update_fallback_ocsp`], which
//! touches the fallback slot alone. SNI-selected and ACME-issued
//! certificates are served unstapled. `rustls` carries the staple on the
//! `CertifiedKey` the resolver hands back per handshake, so a per-host
//! staple is possible; nothing writes one today.
//!
//! # What the fetch asks, and what it checks on the way back
//!
//! The request is the RFC 6960 §4.1.1 `OCSPRequest`, carrying one
//! `CertID` that names the leaf by the hash of its issuer's name, the
//! hash of its issuer's public key, and its own serial number. It goes
//! out as the POST form of RFC 6960 §A.1: `application/ocsp-request`
//! with the DER as the body.
//!
//! Three things are checked before any bytes reach a `CertifiedKey`, and
//! each one refuses a body the fetch used to accept:
//!
//! 1. **The HTTP status.** `reqwest` reports a 4xx as a completed
//!    transfer, so an error page arrives as bytes like any other body.
//!    Only a 200 is read.
//! 2. **The DER envelope.** `stapleable_ocsp_response` requires a
//!    `successful` `OCSPResponse` carrying an `id-pkix-ocsp-basic`
//!    `responseBytes`, which rules out every body that is not an OCSP
//!    response at all.
//! 3. **The `CertID` on the way back.** RFC 6960 §4.2.2.1 has a client
//!    confirm that the certificate a response identifies is the one it
//!    asked about. Without that, a responder, or anything on the
//!    plaintext HTTP hop to it, can answer `good` about some other
//!    certificate and have that answer stapled.
//!
//! # What is not checked: the responder's signature
//!
//! A `BasicOCSPResponse` is signed, either by the issuing CA or by a
//! responder the CA delegated to with an `id-kp-OCSPSigning` extended key
//! usage (RFC 6960 §4.2.2.2). Nothing here verifies that signature or
//! that delegation, and adding it is its own piece of work: it means
//! pulling the responder certificate out of the response, deciding
//! whether the CA authorized it, and verifying a signature over
//! `tbsResponseData` under whichever algorithm the responder chose.
//!
//! What the gap costs is bounded. A forged response cannot make a revoked
//! certificate look good to a client, because a client that reads the
//! staple verifies it against the issuer itself and rejects one that does
//! not verify. What a forged response can do is put bytes on every
//! handshake that such a client then rejects, so the failure mode is lost
//! connections rather than a downgrade, and reaching it means sitting on
//! the plaintext hop to the responder.

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tracing::{error, info};

// --- OcspStapler ---

/// Caches an OCSP response for TLS stapling.
///
/// The cached response is updated by a background task every 12 hours.
/// During a TLS handshake the server can include the stapled response so
/// clients do not need to contact the CA themselves.
pub struct OcspStapler {
    /// Cached OCSP response bytes (`None` until the first successful fetch).
    response: Arc<ArcSwap<Option<Vec<u8>>>>,
    /// WOR-1024: `Instant` of the most recent successful fetch. Used
    /// to drive the `sbproxy_ocsp_staple_age_seconds{host}` gauge so
    /// an operator can spot a stale staple (12h-cadence refresh
    /// loop silently failing) before the cert expires.
    last_fetched_at: Arc<ArcSwap<Option<std::time::Instant>>>,
}

impl OcspStapler {
    /// Create a new stapler with no cached response yet.
    pub fn new() -> Self {
        Self {
            response: Arc::new(ArcSwap::new(Arc::new(None))),
            last_fetched_at: Arc::new(ArcSwap::new(Arc::new(None))),
        }
    }

    /// WOR-1024: age in seconds since the most recent successful fetch.
    /// `None` when the stapler has never fetched a response.
    pub fn staple_age_secs(&self) -> Option<f64> {
        self.last_fetched_at
            .load()
            .as_ref()
            .map(|t| t.elapsed().as_secs_f64())
    }

    /// Publish [`Self::staple_age_secs`] onto
    /// `sbproxy_ocsp_staple_age_seconds{host}` (WOR-2086).
    ///
    /// A stapler that has never fetched publishes nothing, so the
    /// series is *absent* rather than a misleading zero: for a
    /// deployment that expects stapling, "no staple was ever fetched"
    /// is a worse condition than "the staple is old", and an absent
    /// series is what lets an alert tell the two apart.
    ///
    /// Called once a minute by the refresh task's age tick. Before this
    /// existed the gauge was set to `0` on each successful fetch and
    /// then never touched again, so a refresh loop that died left the
    /// gauge frozen at zero: the exact quiet failure the metric was
    /// added to expose.
    pub fn publish_staple_age(&self, host: &str) {
        if let Some(age) = self.staple_age_secs() {
            sbproxy_observe::metrics::record_ocsp_staple_age(host, age);
        }
    }

    /// Test hook: pretend the last successful fetch happened at
    /// `fetched_at`, so age-derived behaviour is deterministic without
    /// a live OCSP responder.
    #[cfg(test)]
    pub(crate) fn mark_fetched_at_for_test(&self, fetched_at: std::time::Instant) {
        self.last_fetched_at.store(Arc::new(Some(fetched_at)));
    }

    /// Fetch the OCSP response for `cert_pem` from the CA's responder URL.
    ///
    /// `cert_pem` is the whole of `proxy.tls_cert_file`, leaf first. Both
    /// certificates in it are used: the leaf supplies the serial number
    /// and the responder URL from its Authority Information Access
    /// extension, and its issuer supplies the public key whose hash tells
    /// the responder which issuer's namespace that serial belongs to.
    ///
    /// Returns the raw DER-encoded OCSP response bytes on success.
    ///
    /// Success means the responder answered on a 200, what it answered
    /// with is a successful basic OCSP response, and that response is
    /// about this certificate. Anything else is refused with the
    /// `unknown_status` outcome rather than returned for stapling, and
    /// the module docs list the three checks and the one deliberate gap.
    pub async fn fetch_ocsp_response(cert_pem: &[u8]) -> Result<Vec<u8>> {
        let (result_label, outcome) = grade_fetch(Self::fetch_ocsp_response_inner(cert_pem).await);
        sbproxy_observe::metrics::record_ocsp_fetch(result_label);
        outcome
    }

    /// Ask the responder, and hand the answer back next to the question.
    ///
    /// # Why POST and not GET
    ///
    /// RFC 6960 §A.1 defines both. GET appends the base64 of the DER,
    /// url-encoded, as a path component, and RFC 5019 §5 asks a
    /// lightweight-profile client to prefer it so that many clients share
    /// one cached answer at the CDN in front of the responder. POST is
    /// taken here anyway, for two reasons. The encoding is the part of
    /// the GET form that goes wrong: `+`, `/`, and `=` all have to
    /// survive a path segment, and a responder that receives a mangled
    /// one answers `malformedRequest`, which is indistinguishable from
    /// the bug this work is fixing. And the caching GET buys is worth
    /// little to this caller in particular, which is one process asking
    /// about one certificate twice a day.
    async fn fetch_ocsp_response_inner(cert_pem: &[u8]) -> Result<FetchedResponse> {
        let target = ocsp_target(cert_pem)?;
        let body = ocsp_request_der(&target.cert_id);

        info!(
            ocsp_url = %target.url,
            request_bytes = body.len(),
            "fetching OCSP response"
        );

        // A background task that awaits a hung fetch inside its select
        // loop stops refreshing and stops publishing the staple age, so
        // the one metric that would show the stall is the one the stall
        // silences. Bound the call rather than rely on the responder.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("building the OCSP HTTP client")?;

        let response = client
            .post(&target.url)
            .header(reqwest::header::CONTENT_TYPE, "application/ocsp-request")
            .body(body)
            .send()
            .await
            .with_context(|| format!("POST {}", target.url))?;

        // Before the body, not after: see `ocsp_http_status`. The URL is
        // deliberately not wrapped around this one, because
        // `classify_fetch_error` reads the rendered message and a
        // responder URL is text nobody here chose.
        ocsp_http_status(response.status())?;

        let bytes = response
            .bytes()
            .await
            .context("reading OCSP response body")?
            .to_vec();

        Ok(FetchedResponse {
            bytes,
            requested: target.cert_id,
        })
    }

    /// Return the currently cached OCSP response, if any.
    pub fn get_response(&self) -> Option<Vec<u8>> {
        self.response.load().as_ref().clone()
    }

    /// Start a background task that fetches the OCSP response now and
    /// refreshes it every 12 hours afterwards.
    ///
    /// On every successful fetch the task:
    /// 1. Stores the bytes in the stapler's cache (so
    ///    [`Self::get_response`] sees them).
    /// 2. Calls `on_update` with a clone of the bytes so the caller
    ///    (typically [`crate::cert_resolver::CertResolver`]) can
    ///    replace its `CertifiedKey` with a new one whose `ocsp`
    ///    field is populated, which is the only mechanism rustls
    ///    0.23 uses to staple a response on the wire.
    ///
    /// The task is fire-and-forget; it logs errors but never panics.
    /// Failures (network blip, OCSP responder down, AIA extension
    /// missing) leave the cached value alone, so a previously-valid
    /// response keeps being stapled until the next successful refresh
    /// or until it expires on the client side.
    ///
    /// `on_update` runs on the spawned task's tokio runtime; keep it
    /// non-blocking and quick. The default 12h cadence matches what
    /// most public CAs (Let's Encrypt, ZeroSSL) recommend; OCSP
    /// responses are usually valid for 7 days but stapling them
    /// fresh shortens the window an attacker has to exploit a
    /// recently-compromised cert.
    ///
    /// `host` is the metric label for the
    /// `sbproxy_ocsp_staple_age_seconds{host}` gauge (WOR-1024). The
    /// manual-fallback cert passes `"_fallback"`; per-host ACME
    /// staples (when they land) pass the SAN they cover.
    pub fn start_refresh_task<F>(&self, host: String, cert_pem: Vec<u8>, on_update: F)
    where
        F: Fn(Vec<u8>) + Send + 'static,
    {
        let response_slot = self.response.clone();
        let last_fetched_slot = self.last_fetched_at.clone();

        crate::maintenance_handle().spawn(async move {
            // --- Initial fetch ---
            //
            // Before the 12h interval, fetch once so the first
            // handshake after startup already gets a stapled
            // response.
            match OcspStapler::fetch_ocsp_response(&cert_pem).await {
                Ok(bytes) => {
                    info!(bytes = bytes.len(), "initial OCSP response fetched");
                    response_slot.store(Arc::new(Some(bytes.clone())));
                    last_fetched_slot.store(Arc::new(Some(std::time::Instant::now())));
                    sbproxy_observe::metrics::record_ocsp_staple_age(&host, 0.0);
                    on_update(bytes);
                }
                Err(e) => {
                    // Don't escalate; the proxy can still serve TLS,
                    // just without stapling. Most clients never
                    // validate OCSP-must-staple unless the cert
                    // requested it.
                    error!("initial OCSP fetch failed: {e:#}");
                }
            }

            // Sibling handle over the same slots, so the age tick
            // below reads through the public accessor rather than
            // duplicating its arithmetic.
            let view = OcspStapler {
                response: response_slot.clone(),
                last_fetched_at: last_fetched_slot.clone(),
            };

            // --- 12h refresh loop + 60s age tick ---
            //
            // WOR-2086: the age gauge is published every minute, not
            // only at fetch time. Publishing only on fetch meant the
            // gauge crawled forward in 12-hour steps at best, and froze
            // at zero if this task died, which is the one failure the
            // gauge exists to make visible. A minute of lag is nothing
            // against a staple lifetime measured in days.
            let mut refresh = tokio::time::interval(std::time::Duration::from_secs(12 * 3600));
            // The first tick fires immediately under tokio's default
            // policy; consume it so the loop sleeps 12h before the
            // first refresh.
            refresh.tick().await;
            let mut age_tick = tokio::time::interval(std::time::Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = refresh.tick() => {
                        match OcspStapler::fetch_ocsp_response(&cert_pem).await {
                            Ok(bytes) => {
                                info!(bytes = bytes.len(), "OCSP response refreshed");
                                response_slot.store(Arc::new(Some(bytes.clone())));
                                last_fetched_slot
                                    .store(Arc::new(Some(std::time::Instant::now())));
                                sbproxy_observe::metrics::record_ocsp_staple_age(&host, 0.0);
                                on_update(bytes);
                            }
                            Err(e) => {
                                // The age tick keeps the gauge moving,
                                // so a failed refresh needs no manual
                                // gauge write here; the staleness is
                                // already visible.
                                error!("failed to refresh OCSP response: {e:#}");
                            }
                        }
                    }
                    _ = age_tick.tick() => {
                        view.publish_staple_age(&host);
                    }
                }
            }
        });
    }
}

impl Default for OcspStapler {
    fn default() -> Self {
        Self::new()
    }
}

// --- Helpers ---

/// Decide what a fetch attempt was worth: the `result` label for
/// `sbproxy_ocsp_fetch_total` and the bytes the caller may staple.
///
/// Split out of [`OcspStapler::fetch_ocsp_response`] because the two halves
/// have very different testability. Fetching needs a responder on the
/// network; deciding whether what came back may be put on the wire is a
/// pure function of the bytes and of the question they claim to answer,
/// and it is the half that can hurt an operator, so it is the half worth
/// pinning in a unit test.
///
/// Both refusals share the `unknown_status` label. `docs/observability.md`
/// and `docs/manual.md` publish five values for `result` and nothing here
/// is worth a sixth: to an operator, a response about another certificate
/// says the same thing as a body that is not an OCSP response at all,
/// which is that bytes came back and none of them may go on the wire.
fn grade_fetch(fetched: Result<FetchedResponse>) -> (&'static str, Result<Vec<u8>>) {
    match fetched {
        Ok(fetched) => match accept_response(&fetched) {
            Ok(()) => ("ok", Ok(fetched.bytes)),
            // Refusing here is the whole point. Stapling bytes that are
            // not a successful OCSP response for this certificate is
            // worse than stapling nothing at all: a client that
            // validates the staple rejects a certificate that is
            // perfectly good, and it fails closed on every connection
            // rather than intermittently.
            Err(e) => ("unknown_status", Err(e)),
        },
        Err(e) => {
            let label = classify_fetch_error(&e);
            (label, Err(e))
        }
    }
}

/// A responder's answer, kept next to the question it was asked.
///
/// The two travel together because neither check that matters can be made
/// from one of them. A grader handed only the bytes cannot tell a response
/// about this certificate from a response about any other, and that is
/// precisely the substitution the `CertID` match exists to catch.
struct FetchedResponse {
    /// The DER the responder returned on a 200.
    bytes: Vec<u8>,
    /// The `CertID` the request carried.
    requested: CertId,
}

/// Both acceptance checks, in the order their error messages read best.
///
/// The envelope check runs first. A body that is not DER at all produces a
/// clearer refusal from `stapleable_ocsp_response` than it would four
/// levels into the `CertID` walk, and the walk has nothing to say about an
/// HTML error page beyond that it is not a SEQUENCE.
///
/// `stapleable_ocsp_response` is left exactly as it was rather than
/// refactored to share this walk. It is the last line of defense, it was
/// reviewed as one piece, and a second independent parse of the same
/// envelope is worth more here than the duplication costs.
fn accept_response(fetched: &FetchedResponse) -> Result<()> {
    stapleable_ocsp_response(&fetched.bytes)?;
    response_answers_for(&fetched.bytes, &fetched.requested)
}

/// Map a transport-or-parse failure onto its `sbproxy_ocsp_fetch_total`
/// `result` label.
fn classify_fetch_error(error: &anyhow::Error) -> &'static str {
    let lower = format!("{error:#}").to_ascii_lowercase();
    if lower.contains("no ocsp responder") || lower.contains("aia extension") {
        "no_responder"
    } else if lower.contains("parse") || lower.contains("certificate") {
        "parse_error"
    } else {
        "http_error"
    }
}

// --- DER, the write side ---

// Tags used by the request builder and the response matcher. Deliberately
// separate from the constants inside `stapleable_ocsp_response`, which is
// left exactly as it was reviewed.
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_ENUMERATED: u8 = 0x0A;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
/// `[0]` explicit, constructed.
const TAG_CONTEXT_0: u8 = 0xA0;
/// `[1]` explicit, constructed.
const TAG_CONTEXT_1: u8 = 0xA1;
/// `[2]` explicit, constructed.
const TAG_CONTEXT_2: u8 = 0xA2;

/// DER-encode one tag-length-value.
///
/// The write side of `read_tlv`, and the only place a length is encoded,
/// so the shortest-definite-length rule that `read_tlv` enforces on the
/// way in is satisfied by construction on the way out.
fn write_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = Vec::with_capacity(len + 6);
    out.push(tag);
    if len < 0x80 {
        // Short form. The branch condition is the proof the cast is exact.
        out.push(len as u8);
    } else {
        // Long form, big-endian, leading zero octets dropped so the
        // encoding is the shortest one that holds the length. `len` is at
        // least 0x80 here, so at least one octet survives the trim.
        let be = len.to_be_bytes();
        let mut significant = &be[..];
        while significant.first() == Some(&0) {
            significant = &significant[1..];
        }
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(contents);
    out
}

/// Read one TLV of the expected `tag`, naming `what` when it is not there.
///
/// Returns `(contents, remainder)`. Every DER step below goes through this
/// or through `take_tlv_raw`, so no step is written as an index or an
/// unwrap: a responder chooses these bytes and a malformed answer has to
/// come back as an error an operator can read.
fn take_tlv<'a>(input: &'a [u8], tag: u8, what: &str) -> Result<(&'a [u8], &'a [u8])> {
    let Some((found, contents, rest)) = read_tlv(input) else {
        bail!("{what} is missing or is not well-formed DER");
    };
    if found != tag {
        bail!("{what} has DER tag 0x{found:02X} where 0x{tag:02X} was required");
    }
    Ok((contents, rest))
}

/// `take_tlv`, returning the whole tag-length-value rather than its
/// contents, for the one place that has to hand a nested structure on with
/// its header intact: comparing a `CertID`.
fn take_tlv_raw<'a>(input: &'a [u8], tag: u8, what: &str) -> Result<(&'a [u8], &'a [u8])> {
    let (_, rest) = take_tlv(input, tag, what)?;
    // `rest` is a suffix of `input`, so the difference is the length of
    // the value just read and the slice below is in bounds.
    let consumed = input.len() - rest.len();
    Ok((&input[..consumed], rest))
}

/// SHA-1 of `data`, through `ring`, which this crate already depends on.
///
/// The hash is not a choice. RFC 5019 §2.1.1 fixes SHA-1 as the `CertID`
/// hash for the lightweight profile that public responders implement, and
/// they index their pre-produced responses by it, so a request under a
/// stronger hash is answered `unauthorized` rather than answered better.
/// What the hash does here is name a certificate; what makes a response
/// trustworthy is the responder signature, which the client verifies.
fn sha1(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec()
}

/// DER encoding of the SHA-1 OID, `1.3.14.3.2.26`, contents only.
const ID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];

/// DER encoding of the `id-pkix-ocsp-basic` OID, `1.3.6.1.5.5.7.48.1.1`,
/// contents only. RFC 6960 §4.2.1 defines it as the one `responseType` a
/// responder must produce and a client must understand.
const ID_PKIX_OCSP_BASIC: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

// --- CertID ---

/// RFC 6960 §4.1.1 `CertID`: which certificate a request asks about, and
/// which certificate a response answers about.
///
/// ```text
/// CertID ::= SEQUENCE {
///     hashAlgorithm   AlgorithmIdentifier,
///     issuerNameHash  OCTET STRING,
///     issuerKeyHash   OCTET STRING,
///     serialNumber    CertificateSerialNumber }
/// ```
///
/// The serial alone does not identify a certificate: serials are unique
/// per issuer, so the two hashes are what say which issuer's numbering is
/// meant. `hashAlgorithm` is not a field here because only SHA-1 is
/// written and only SHA-1 is accepted; `CertId::from_der` refuses anything
/// else rather than carrying it into a comparison that could then never
/// match for a reason the log would not name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CertId {
    /// SHA-1 over the DER of the issuer's `Name`.
    issuer_name_hash: Vec<u8>,
    /// SHA-1 over the value of the issuer's `subjectPublicKey` BIT STRING,
    /// excluding the tag, the length, and the unused-bits octet.
    issuer_key_hash: Vec<u8>,
    /// The leaf's `serialNumber`, kept as the INTEGER contents the issuer
    /// encoded so that re-encoding cannot change it.
    serial: Vec<u8>,
}

impl CertId {
    /// Encode as the `CertID` of RFC 6960 §4.1.1.
    fn to_der(&self) -> Vec<u8> {
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
        //
        // RFC 3279 §2.1 makes the SHA-1 parameters optional and requires a
        // NULL when they are present. The NULL is written because that is
        // the encoding in common use; `Self::from_der` accepts either, so
        // a responder that omits it still matches.
        let mut algorithm = write_tlv(TAG_OID, ID_SHA1);
        algorithm.extend_from_slice(&write_tlv(TAG_NULL, &[]));

        let mut contents = write_tlv(TAG_SEQUENCE, &algorithm);
        contents.extend_from_slice(&write_tlv(TAG_OCTET_STRING, &self.issuer_name_hash));
        contents.extend_from_slice(&write_tlv(TAG_OCTET_STRING, &self.issuer_key_hash));
        contents.extend_from_slice(&write_tlv(TAG_INTEGER, &self.serial));
        write_tlv(TAG_SEQUENCE, &contents)
    }

    /// Decode a `CertID`, refusing any hash other than SHA-1.
    fn from_der(bytes: &[u8]) -> Result<Self> {
        let (contents, trailing) = take_tlv(bytes, TAG_SEQUENCE, "CertID")?;
        if !trailing.is_empty() {
            bail!(
                "CertID is followed by {} octets that are not its own",
                trailing.len()
            );
        }

        let (algorithm, contents) = take_tlv(contents, TAG_SEQUENCE, "CertID hashAlgorithm")?;
        // The remainder of the AlgorithmIdentifier is `parameters`, which
        // is read and discarded: NULL and absent both mean SHA-1.
        let (oid, _parameters) = take_tlv(algorithm, TAG_OID, "CertID hashAlgorithm algorithm")?;
        if oid != ID_SHA1 {
            bail!("CertID names a hash other than the SHA-1 this request asked under");
        }

        let (issuer_name_hash, contents) =
            take_tlv(contents, TAG_OCTET_STRING, "CertID issuerNameHash")?;
        let (issuer_key_hash, contents) =
            take_tlv(contents, TAG_OCTET_STRING, "CertID issuerKeyHash")?;
        let (serial, rest) = take_tlv(contents, TAG_INTEGER, "CertID serialNumber")?;
        if !rest.is_empty() {
            bail!(
                "CertID carries {} octets after its serialNumber",
                rest.len()
            );
        }

        Ok(Self {
            issuer_name_hash: issuer_name_hash.to_vec(),
            issuer_key_hash: issuer_key_hash.to_vec(),
            serial: serial.to_vec(),
        })
    }
}

// --- Building the question ---

/// What a fetch needs before it can ask anything.
///
/// `Debug` is derived so a test can `expect_err` on a `Result<OcspTarget>`
/// and say what came back instead of an error.
#[derive(Debug)]
struct OcspTarget {
    /// The `id-ad-ocsp` responder URL from the leaf's AIA extension.
    url: String,
    /// RFC 6960 §4.1.1 `CertID` naming the leaf under its issuer.
    cert_id: CertId,
}

/// Read the leaf and its issuer out of `cert_pem` and build the question.
///
/// # Where the issuer comes from
///
/// `TlsState::init` reads `proxy.tls_cert_file` whole into the buffer that
/// arrives here, and rustls needs the issuing chain in that same file in
/// order to send it during a handshake, so on any deployment serving a
/// chain at all the issuer is already in these bytes. Nothing had to move
/// to reach it: the previous code parsed every certificate in the buffer
/// and then used only the first.
///
/// The issuer is chosen by comparing the DER of the leaf's `issuer` field
/// against the DER of each certificate's `subject` field, rather than by
/// taking the second entry. A chain file is conventionally leaf first and
/// nothing enforces the order of what follows it, and the wrong
/// certificate here produces an `issuerKeyHash` no responder recognizes,
/// which comes back as `unauthorized` and reads like a network problem.
///
/// A file holding only the leaf is refused, and the refusal says so.
/// Fetching the issuer from the AIA `id-ad-caIssuers` URL would also work
/// and is deliberately not done: that is a second unauthenticated fetch,
/// and its answer would feed the hash that decides which certificate the
/// whole exchange is about.
fn ocsp_target(cert_pem: &[u8]) -> Result<OcspTarget> {
    use rustls::pki_types::{pem::PemObject as _, CertificateDer};
    use x509_parser::prelude::*;

    let der_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .filter_map(|r| r.ok())
        .collect();
    let leaf_der = der_certs.first().context("no certificate found in PEM")?;
    let (_, leaf) =
        X509Certificate::from_der(leaf_der.as_ref()).context("failed to parse certificate DER")?;

    let url = extract_ocsp_url(&leaf)
        .context("certificate has no OCSP responder URL in AIA extension")?;

    // RFC 6960 §4.1.1 takes `issuerNameHash` over the DER of the issuer's
    // name as it appears in the certificate being checked, so what gets
    // hashed is the leaf's own `issuer` field rather than the issuer
    // certificate's `subject`. The two encode the same name; only one of
    // them is the encoding the leaf was signed over.
    let issuer_name = leaf.issuer().as_raw();

    let issuer_key_hash = der_certs
        .iter()
        .filter_map(|der| {
            X509Certificate::from_der(der.as_ref())
                .ok()
                .map(|(_, candidate)| candidate)
        })
        .find(|candidate| candidate.subject().as_raw() == issuer_name)
        // `BitString::data` is the value of the BIT STRING with the
        // unused-bits octet already stripped, which is exactly what
        // `issuerKeyHash` is taken over.
        .map(|issuer| sha1(issuer.public_key().subject_public_key.data.as_ref()));

    let Some(issuer_key_hash) = issuer_key_hash else {
        bail!(
            "the TLS certificate file holds no issuer for its leaf, and an OCSP request \
             cannot name a certificate without hashing the issuer's public key. Point \
             proxy.tls_cert_file at the full chain, leaf first."
        );
    };

    Ok(OcspTarget {
        url,
        cert_id: CertId {
            issuer_name_hash: sha1(issuer_name),
            issuer_key_hash,
            serial: leaf.raw_serial().to_vec(),
        },
    })
}

/// Encode the RFC 6960 §4.1.1 `OCSPRequest` that asks about one
/// certificate.
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///     tbsRequest              TBSRequest,
///     optionalSignature   [0] EXPLICIT Signature OPTIONAL }
///
/// TBSRequest ::= SEQUENCE {
///     version             [0] EXPLICIT Version DEFAULT v1,
///     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
///     requestList             SEQUENCE OF Request,
///     requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
///
/// Request ::= SEQUENCE {
///     reqCert                     CertID,
///     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// Every optional field is omitted, so the encoding is four nested
/// SEQUENCEs around one `CertID`. `version` is v1 and DER omits a field
/// sitting at its default. The request is unsigned, which is what
/// `optionalSignature` being optional is for; a responder that wanted one
/// would answer `sigRequired`, and public CAs do not.
///
/// # No nonce
///
/// RFC 6960 §4.4.1 defines a nonce extension that binds a response to one
/// request. It is deliberately not sent. RFC 5019 §2.2.1 has responders
/// pre-produce and cache their answers, which a nonce defeats by
/// construction, so a nonced request is commonly refused or has its nonce
/// dropped. What a nonce buys is replay protection, and a staple is a
/// replayed response by design: it is fetched twice a day and served to
/// every client in between. `nextUpdate` is what bounds that, and the
/// client is what checks it.
fn ocsp_request_der(cert_id: &CertId) -> Vec<u8> {
    let request = write_tlv(TAG_SEQUENCE, &cert_id.to_der());
    let request_list = write_tlv(TAG_SEQUENCE, &request);
    let tbs_request = write_tlv(TAG_SEQUENCE, &request_list);
    write_tlv(TAG_SEQUENCE, &tbs_request)
}

// --- Checking the answer ---

/// Refuse anything but a 200, before the body is read.
///
/// RFC 6960 §A.2 puts the DER of the `OCSPResponse` in the body of the
/// HTTP response, so a non-200 body is the responder, or something in
/// front of it, saying it did not answer. `reqwest` reports a 4xx as a
/// completed transfer and hands the error page over as bytes like any
/// other body, and before this existed those bytes were read as DER.
fn ocsp_http_status(status: reqwest::StatusCode) -> Result<()> {
    if status == reqwest::StatusCode::OK {
        return Ok(());
    }
    bail!("responder answered HTTP {status}, and an OCSPResponse only ever arrives on a 200");
}

/// Walk into a `BasicOCSPResponse` and return the contents of each
/// `SingleResponse`, so the caller reads its `certID` as the first field.
///
/// RFC 6960 §4.2.1:
///
/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///     tbsResponseData     ResponseData,
///     signatureAlgorithm  AlgorithmIdentifier,
///     signature           BIT STRING,
///     certs           [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
///
/// ResponseData ::= SEQUENCE {
///     version             [0] EXPLICIT Version DEFAULT v1,
///     responderID             ResponderID,
///     producedAt              GeneralizedTime,
///     responses               SEQUENCE OF SingleResponse,
///     responseExtensions  [1] EXPLICIT Extensions OPTIONAL }
///
/// SingleResponse ::= SEQUENCE {
///     certID                  CertID,
///     certStatus              CertStatus,
///     thisUpdate              GeneralizedTime,
///     nextUpdate      [0]     EXPLICIT GeneralizedTime OPTIONAL,
///     singleExtensions [1]    EXPLICIT Extensions OPTIONAL }
/// ```
///
/// `signature` and `certs` are read past rather than read: verifying the
/// responder is the follow-up the module docs describe.
fn single_responses(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    // OCSPResponse ::= SEQUENCE { responseStatus, responseBytes [0] OPTIONAL }
    let (envelope, _) = take_tlv(bytes, TAG_SEQUENCE, "OCSPResponse")?;
    let (_, after_status) = take_tlv(envelope, TAG_ENUMERATED, "OCSPResponse responseStatus")?;
    let (explicit, _) = take_tlv(after_status, TAG_CONTEXT_0, "OCSPResponse responseBytes")?;

    // ResponseBytes ::= SEQUENCE { responseType OBJECT IDENTIFIER, response OCTET STRING }
    let (response_bytes, _) = take_tlv(explicit, TAG_SEQUENCE, "ResponseBytes")?;
    let (_, after_oid) = take_tlv(response_bytes, TAG_OID, "ResponseBytes responseType")?;
    let (basic, _) = take_tlv(after_oid, TAG_OCTET_STRING, "ResponseBytes response")?;

    let (basic, _) = take_tlv(basic, TAG_SEQUENCE, "BasicOCSPResponse")?;
    let (tbs, _) = take_tlv(basic, TAG_SEQUENCE, "BasicOCSPResponse tbsResponseData")?;

    // ResponseData is walked in order rather than by tag. `responderID`'s
    // byName arm and `responseExtensions` are both `[1]`, so position is
    // the only thing that tells the two apart.
    let mut cursor = tbs;
    if matches!(read_tlv(cursor), Some((tag, _, _)) if tag == TAG_CONTEXT_0) {
        // DER omits a field sitting at its default, so a `version` here
        // means a responder wrote v1 out anyway. Skip it either way.
        let (_, rest) = take_tlv(cursor, TAG_CONTEXT_0, "ResponseData version")?;
        cursor = rest;
    }

    // ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }
    let responder_id_tag = match read_tlv(cursor) {
        Some((tag, _, _)) if tag == TAG_CONTEXT_1 => TAG_CONTEXT_1,
        _ => TAG_CONTEXT_2,
    };
    let (_, cursor) = take_tlv(cursor, responder_id_tag, "ResponseData responderID")?;
    let (_, cursor) = take_tlv(cursor, TAG_GENERALIZED_TIME, "ResponseData producedAt")?;
    let (responses, _) = take_tlv(cursor, TAG_SEQUENCE, "ResponseData responses")?;

    let mut out = Vec::new();
    let mut rest = responses;
    while !rest.is_empty() {
        let (single, next) = take_tlv(rest, TAG_SEQUENCE, "SingleResponse")?;
        out.push(single);
        rest = next;
    }
    Ok(out)
}

/// Refuse a response that does not answer about the certificate the
/// request asked about.
///
/// This is the check that makes the rest of the fetch worth anything, and
/// it is the one easiest to leave out, because everything looks correct
/// without it: the responder is reachable, the DER parses, the status is
/// `successful`, and the staple goes on the wire. RFC 6960 §4.2.2.1 has a
/// client confirm that the certificate a response identifies is the one it
/// asked about, and the reason is that a responder, or anything sitting on
/// the plaintext HTTP hop to it, can otherwise return a well-formed and
/// correctly signed `good` response about a different certificate
/// entirely.
///
/// Comparison is over the decoded fields rather than the raw `CertID`
/// bytes, so a responder that omits the optional SHA-1 NULL parameters
/// still matches. The three values that name the certificate all have to
/// be equal.
fn response_answers_for(bytes: &[u8], requested: &CertId) -> Result<()> {
    let singles = single_responses(bytes)?;
    if singles.is_empty() {
        bail!("responder returned an empty responses list, so it answered about nothing");
    }

    let mut unreadable = 0usize;
    for single in singles.iter().copied() {
        let (cert_id, _) = take_tlv_raw(single, TAG_SEQUENCE, "SingleResponse certID")?;
        match CertId::from_der(cert_id) {
            Ok(answered) if answered == *requested => return Ok(()),
            Ok(_) => {}
            Err(_) => unreadable += 1,
        }
    }

    bail!(
        "responder returned {} SingleResponse entries ({unreadable} of them unreadable) and \
         none of them carries the CertID this request asked about",
        singles.len()
    );
}

/// Return `Ok(())` when `bytes` are a successful basic OCSP response and so
/// may be stapled, and an error naming the reason when they are not.
///
/// RFC 6960 §4.2.1:
///
/// ```text
/// OCSPResponse ::= SEQUENCE {
///    responseStatus   OCSPResponseStatus,
///    responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL }
///
/// OCSPResponseStatus ::= ENUMERATED {
///    successful(0), malformedRequest(1), internalError(2),
///    tryLater(3), sigRequired(5), unauthorized(6) }
///
/// ResponseBytes ::= SEQUENCE {
///    responseType   OBJECT IDENTIFIER,
///    response       OCTET STRING }
/// ```
///
/// This checks the shape and the status, not the signature or the
/// certificate the response is about. It cannot check those: the fetch does
/// not send an `OCSPRequest`, so there is no `CertID` to match a response
/// against. What it does rule out is the whole class of bytes that are not
/// an OCSP response at all, which is what a responder returns to a request
/// that named no certificate.
fn stapleable_ocsp_response(bytes: &[u8]) -> Result<()> {
    const SEQUENCE: u8 = 0x30;
    const ENUMERATED: u8 = 0x0A;
    const OCTET_STRING: u8 = 0x04;
    const OBJECT_IDENTIFIER: u8 = 0x06;
    // `[0]` explicit, constructed.
    const CONTEXT_0: u8 = 0xA0;

    let Some((tag, body, after)) = read_tlv(bytes) else {
        bail!("responder returned {} bytes that are not DER", bytes.len());
    };
    if tag != SEQUENCE || !after.is_empty() {
        bail!("responder returned DER that is not a single OCSPResponse SEQUENCE");
    }

    let Some((tag, status, after_status)) = read_tlv(body) else {
        bail!("OCSPResponse carries no responseStatus");
    };
    if tag != ENUMERATED {
        bail!("OCSPResponse responseStatus is not an ENUMERATED");
    }
    // Every status RFC 6960 defines fits in one octet, and DER encodes an
    // ENUMERATED in the fewest octets that hold it.
    let [status] = status else {
        bail!("OCSPResponse responseStatus is not a single octet");
    };
    if *status != 0 {
        bail!("{}", response_status_name(*status));
    }

    let Some((tag, response_bytes, after_bytes)) = read_tlv(after_status) else {
        // Legal DER, and useless: `successful` with no `responseBytes` has
        // nothing in it to staple.
        bail!("OCSPResponse is successful but carries no responseBytes");
    };
    if tag != CONTEXT_0 || !after_bytes.is_empty() {
        bail!("OCSPResponse responseBytes is not a [0] EXPLICIT field");
    }

    let Some((tag, inner, after_inner)) = read_tlv(response_bytes) else {
        bail!("OCSPResponse responseBytes holds no ResponseBytes SEQUENCE");
    };
    if tag != SEQUENCE || !after_inner.is_empty() {
        bail!("OCSPResponse responseBytes is not a single ResponseBytes SEQUENCE");
    }

    let Some((tag, oid, after_oid)) = read_tlv(inner) else {
        bail!("ResponseBytes carries no responseType");
    };
    if tag != OBJECT_IDENTIFIER {
        bail!("ResponseBytes responseType is not an OBJECT IDENTIFIER");
    }
    if oid != ID_PKIX_OCSP_BASIC {
        bail!("ResponseBytes responseType is not id-pkix-ocsp-basic");
    }

    let Some((tag, response, after_response)) = read_tlv(after_oid) else {
        bail!("ResponseBytes carries no response");
    };
    if tag != OCTET_STRING || !after_response.is_empty() {
        bail!("ResponseBytes response is not a single OCTET STRING");
    }
    if response.is_empty() {
        bail!("ResponseBytes response is an empty OCTET STRING");
    }

    Ok(())
}

/// Name a non-successful `OCSPResponseStatus` so the log says what the
/// responder actually refused with rather than a bare number. RFC 6960
/// §4.2.1; `4` is unassigned.
fn response_status_name(status: u8) -> String {
    let name = match status {
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => "an unassigned status",
    };
    format!("responder answered with {name} ({status}), not a stapleable response")
}

/// Read the DER tag-length-value at the front of `input`.
///
/// Returns `(tag, contents, remainder)`, or `None` when `input` does not
/// begin with one well-formed definite-length TLV. Deliberately strict:
/// this reads bytes an unauthenticated responder sent, and the alternative
/// to rejecting an oddly-encoded response is putting it on the wire.
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = input.split_first()?;
    // High-tag-number form. Nothing in an OCSPResponse uses it, so refuse
    // rather than decode a shape that cannot legitimately appear.
    if tag & 0x1F == 0x1F {
        return None;
    }

    let (&first_len, after_first_len) = after_tag.split_first()?;
    let (len, after_len) = if first_len & 0x80 == 0 {
        (usize::from(first_len), after_first_len)
    } else {
        let count = usize::from(first_len & 0x7F);
        // `0` is BER's indefinite length, which DER forbids. Past four
        // octets the claimed length exceeds any OCSP response worth
        // reading, and on a 32-bit target it would also overflow `usize`.
        if count == 0 || count > 4 || after_first_len.len() < count {
            return None;
        }
        let (len_bytes, rest) = after_first_len.split_at(count);
        // DER requires the shortest form, so a leading zero octet means
        // the sender is not speaking DER.
        if len_bytes.first() == Some(&0) {
            return None;
        }
        let mut len = 0usize;
        for byte in len_bytes {
            len = (len << 8) | usize::from(*byte);
        }
        (len, rest)
    };

    if after_len.len() < len {
        return None;
    }
    let (contents, rest) = after_len.split_at(len);
    Some((tag, contents, rest))
}

/// Extract the first OCSP responder URL from a certificate's AIA extension.
fn extract_ocsp_url(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::extensions::ParsedExtension;

    let aia = cert.extensions().iter().find_map(|ext| {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            Some(aia)
        } else {
            None
        }
    })?;

    for access in &aia.accessdescs {
        // OID 1.3.6.1.5.5.7.48.1 = id-ad-ocsp
        if access.access_method.to_string() == "1.3.6.1.5.5.7.48.1" {
            if let GeneralName::URI(uri) = &access.access_location {
                return Some(uri.to_string());
            }
        }
    }

    None
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staple_age_is_absent_until_fetch_then_tracks_elapsed_time() {
        // WOR-2086, through the stapler rather than the recorder: a
        // never-fetched stapler publishes no series at all, and a
        // fetched one publishes its real elapsed age. Distinct hosts
        // per assertion because the prometheus default registry is
        // process-global across tests.
        let stapler = OcspStapler::new();
        assert!(stapler.staple_age_secs().is_none());
        stapler.publish_staple_age("never-fetched.test");

        let gauge_for = |host: &str| -> Option<f64> {
            prometheus::default_registry()
                .gather()
                .iter()
                .find(|f| f.name() == "sbproxy_ocsp_staple_age_seconds")
                .and_then(|f| {
                    f.get_metric()
                        .iter()
                        .find(|m| {
                            m.get_label()
                                .iter()
                                .any(|l| l.name() == "host" && l.value() == host)
                        })
                        .map(|m| m.get_gauge().value())
                })
        };

        assert!(
            gauge_for("never-fetched.test").is_none(),
            "a stapler that never fetched must leave the series absent, not zero"
        );

        let fetched_at = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(90))
            .expect("monotonic clock is older than 90s");
        stapler.mark_fetched_at_for_test(fetched_at);
        let age = stapler
            .staple_age_secs()
            .expect("fetched stapler has an age");
        assert!(age >= 90.0, "age must track elapsed time, got {age}");

        stapler.publish_staple_age("staple-age.test");
        let published =
            gauge_for("staple-age.test").expect("a fetched stapler must publish its age");
        assert!(
            published >= 90.0,
            "the gauge must carry the real age, got {published}"
        );
    }

    #[test]
    fn new_stapler_has_no_response() {
        let stapler = OcspStapler::new();
        assert!(
            stapler.get_response().is_none(),
            "freshly created stapler should have no cached response"
        );
    }

    #[test]
    fn default_stapler_has_no_response() {
        let stapler = OcspStapler::default();
        assert!(stapler.get_response().is_none());
    }

    #[test]
    fn fetch_ocsp_rejects_empty_pem() {
        // An empty PEM slice must yield an error, not a panic.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(OcspStapler::fetch_ocsp_response(b""));
        assert!(result.is_err(), "empty PEM should return an error");
    }

    #[test]
    fn fetch_ocsp_rejects_garbage_pem() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(OcspStapler::fetch_ocsp_response(b"not a real cert"));
        assert!(result.is_err());
    }

    // --- What may be stapled (WOR-2310) ---

    /// DER tag-length-value, short form only, which is all these fixtures
    /// need. `long_form_len` covers the other branch on its own.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        assert!(contents.len() < 128, "fixture is short-form only");
        let mut out = vec![tag, contents.len() as u8];
        out.extend_from_slice(contents);
        out
    }

    /// A well-formed `OCSPResponse` with the given status. When
    /// `with_bytes`, it also carries an `id-pkix-ocsp-basic`
    /// `responseBytes` holding a stand-in payload: the payload is opaque
    /// to the validator, which checks the envelope rather than the
    /// signed `BasicOCSPResponse` inside it.
    fn ocsp_response(status: u8, with_bytes: bool) -> Vec<u8> {
        let mut body = tlv(0x0A, &[status]);
        if with_bytes {
            let mut response_bytes = tlv(0x06, ID_PKIX_OCSP_BASIC);
            response_bytes.extend_from_slice(&tlv(0x04, b"signed-basic-response"));
            body.extend_from_slice(&tlv(0xA0, &tlv(0x30, &response_bytes)));
        }
        tlv(0x30, &body)
    }

    #[test]
    fn a_successful_basic_response_is_stapleable() {
        stapleable_ocsp_response(&ocsp_response(0, true))
            .expect("a successful basic OCSP response is exactly what stapling wants");
    }

    #[test]
    fn a_non_successful_status_is_never_stapled() {
        // The status a responder returns to a request that named no
        // certificate, which is the request this crate sends today.
        for (status, name) in [
            (1u8, "malformedRequest"),
            (2, "internalError"),
            (3, "tryLater"),
            (5, "sigRequired"),
            (6, "unauthorized"),
        ] {
            let err = stapleable_ocsp_response(&ocsp_response(status, true))
                .err()
                .unwrap_or_else(|| panic!("status {status} must not be stapleable"));
            let message = format!("{err:#}");
            assert!(
                message.contains(name),
                "the log has to name the refusal, got {message}"
            );
        }
    }

    #[test]
    fn an_http_error_page_is_never_stapled() {
        // `reqwest::get` reports a 4xx as a completed transfer, so the
        // body of an error page reaches the stapler as bytes. Before
        // WOR-2310 those bytes were cached and put on the wire.
        let err = stapleable_ocsp_response(b"<html><body>400 Bad Request</body></html>")
            .expect_err("an HTML error page is not an OCSP response");
        assert!(format!("{err:#}").contains("not DER"));
    }

    #[test]
    fn a_successful_response_with_no_response_bytes_is_never_stapled() {
        // Legal DER and empty of anything to staple.
        stapleable_ocsp_response(&ocsp_response(0, false))
            .expect_err("successful with no responseBytes has nothing in it");
    }

    #[test]
    fn a_foreign_response_type_is_never_stapled() {
        let mut response_bytes = tlv(
            0x06,
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02],
        );
        response_bytes.extend_from_slice(&tlv(0x04, b"payload"));
        let mut body = tlv(0x0A, &[0]);
        body.extend_from_slice(&tlv(0xA0, &tlv(0x30, &response_bytes)));
        let err = stapleable_ocsp_response(&tlv(0x30, &body))
            .expect_err("only id-pkix-ocsp-basic may be stapled");
        assert!(format!("{err:#}").contains("id-pkix-ocsp-basic"));
    }

    #[test]
    fn trailing_bytes_after_the_response_are_never_stapled() {
        let mut bytes = ocsp_response(0, true);
        bytes.extend_from_slice(b"and then some");
        stapleable_ocsp_response(&bytes)
            .expect_err("a response with a tail is not a single OCSPResponse");
    }

    #[test]
    fn empty_bytes_are_never_stapled() {
        stapleable_ocsp_response(b"").expect_err("no bytes is not a response");
    }

    #[test]
    fn read_tlv_accepts_the_long_form_and_refuses_ber() {
        // Long form, two length octets, 200 bytes of contents.
        let mut long = vec![0x04, 0x81, 200];
        long.extend_from_slice(&[0xAA; 200]);
        let (tag, contents, rest) = read_tlv(&long).expect("long form is definite-length DER");
        assert_eq!(tag, 0x04);
        assert_eq!(contents.len(), 200);
        assert!(rest.is_empty());

        // Indefinite length is BER, not DER.
        assert!(read_tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
        // Non-minimal length encoding is not DER either.
        assert!(read_tlv(&[0x04, 0x82, 0x00, 0x01, 0xAA]).is_none());
        // A length that runs past the buffer must not panic or truncate.
        assert!(read_tlv(&[0x04, 0x10, 0xAA]).is_none());
    }

    #[test]
    fn grade_fetch_refuses_unstapleable_bytes_as_unknown_status() {
        // The behaviour WOR-2310 changes, at the seam that decides it.
        // Before, any bytes a responder returned were graded "ok" and
        // handed back for stapling.
        let (label, outcome) = grade_fetch(Ok(FetchedResponse {
            bytes: b"400 Bad Request".to_vec(),
            requested: test_cert_id(0x11),
        }));
        assert_eq!(label, "unknown_status");
        assert!(
            outcome.is_err(),
            "bytes that are not an OCSP response must not reach a CertifiedKey"
        );
    }

    #[test]
    fn grade_fetch_passes_a_real_response_through_as_ok() {
        let asked = test_cert_id(0x11);
        let bytes = ocsp_response_about(std::slice::from_ref(&asked));
        let (label, outcome) = grade_fetch(Ok(FetchedResponse {
            bytes: bytes.clone(),
            requested: asked,
        }));
        assert_eq!(label, "ok");
        assert_eq!(outcome.ok(), Some(bytes));
    }

    #[test]
    fn grade_fetch_keeps_the_existing_transport_labels() {
        let cases = [
            (
                "certificate has no OCSP responder URL in AIA extension",
                "no_responder",
            ),
            ("failed to parse certificate DER", "parse_error"),
            ("GET http://ocsp.example/: connection refused", "http_error"),
        ];
        for (message, expected) in cases {
            let (label, outcome) = grade_fetch(Err(anyhow::anyhow!("{message}")));
            assert_eq!(label, expected, "label drifted for {message}");
            assert!(outcome.is_err());
        }
    }

    #[test]
    fn get_response_reflects_stored_value() {
        // Manually store a response and verify get_response returns it.
        let stapler = OcspStapler::new();
        let dummy: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        stapler.response.store(Arc::new(Some(dummy.clone())));
        let got = stapler
            .get_response()
            .expect("should return stored response");
        assert_eq!(got, dummy);
    }

    // --- Asking the right question, and checking the answer (WOR-2322) ---

    /// The responder URL the test chain's AIA extension points at.
    const TEST_OCSP_URL: &str = "http://ocsp.test.invalid/";

    /// The leaf serial the test chain is issued with. High bit clear and no
    /// leading zero octet, so the DER INTEGER contents are these four bytes
    /// and nothing has to be reasoned about padding.
    const TEST_SERIAL: &[u8] = &[0x2A, 0x0B, 0x7F, 0x11];

    /// A `CertID` whose three fields are distinguishable at a glance.
    fn test_cert_id(seed: u8) -> CertId {
        CertId {
            issuer_name_hash: vec![seed; 20],
            issuer_key_hash: vec![seed.wrapping_add(0x40); 20],
            serial: TEST_SERIAL.to_vec(),
        }
    }

    /// A complete `OCSPResponse` carrying one `SingleResponse` per `CertID`.
    ///
    /// Everything the matcher walks past is present and everything it reads
    /// is real, so a response built here is refused only for the reason a
    /// test is about. The `signature` is a stand-in, which is exactly the
    /// gap the module docs name: nothing in this crate verifies it.
    fn ocsp_response_about(cert_ids: &[CertId]) -> Vec<u8> {
        const TAG_BIT_STRING: u8 = 0x03;
        // `good` is the `[0] IMPLICIT NULL` arm of `CertStatus`.
        const TAG_GOOD: u8 = 0x80;
        const A_TIME: &[u8] = b"20260101000000Z";

        let mut responses = Vec::new();
        for cert_id in cert_ids {
            let mut single = cert_id.to_der();
            single.extend_from_slice(&write_tlv(TAG_GOOD, &[]));
            single.extend_from_slice(&write_tlv(TAG_GENERALIZED_TIME, A_TIME));
            responses.extend_from_slice(&write_tlv(TAG_SEQUENCE, &single));
        }

        // ResponseData. `responderID` takes its byKey arm so the walk has
        // to handle `[2]` and not only the `[1]` that collides with
        // `responseExtensions`.
        let mut tbs = write_tlv(TAG_CONTEXT_2, &write_tlv(TAG_OCTET_STRING, &[0xAB; 20]));
        tbs.extend_from_slice(&write_tlv(TAG_GENERALIZED_TIME, A_TIME));
        tbs.extend_from_slice(&write_tlv(TAG_SEQUENCE, &responses));

        let mut basic = write_tlv(TAG_SEQUENCE, &tbs);
        basic.extend_from_slice(&write_tlv(TAG_SEQUENCE, &write_tlv(TAG_OID, ID_SHA1)));
        basic.extend_from_slice(&write_tlv(TAG_BIT_STRING, &[0x00, 0xDE, 0xAD]));

        let mut response_bytes = write_tlv(TAG_OID, ID_PKIX_OCSP_BASIC);
        response_bytes.extend_from_slice(&write_tlv(
            TAG_OCTET_STRING,
            &write_tlv(TAG_SEQUENCE, &basic),
        ));

        let mut body = write_tlv(TAG_ENUMERATED, &[0]);
        body.extend_from_slice(&write_tlv(
            TAG_CONTEXT_0,
            &write_tlv(TAG_SEQUENCE, &response_bytes),
        ));
        write_tlv(TAG_SEQUENCE, &body)
    }

    /// The AIA extension contents naming `TEST_OCSP_URL` as the responder.
    ///
    /// ```text
    /// AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
    /// AccessDescription ::= SEQUENCE {
    ///     accessMethod    OBJECT IDENTIFIER,
    ///     accessLocation  GeneralName }
    /// ```
    ///
    /// `accessMethod` is `id-ad-ocsp`, 1.3.6.1.5.5.7.48.1, and
    /// `accessLocation` is the `uniformResourceIdentifier` arm of
    /// `GeneralName`, which is context tag 6, primitive.
    fn aia_extension_der() -> Vec<u8> {
        const ID_AD_OCSP: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
        const TAG_GENERAL_NAME_URI: u8 = 0x86;

        let mut description = write_tlv(TAG_OID, ID_AD_OCSP);
        description.extend_from_slice(&write_tlv(TAG_GENERAL_NAME_URI, TEST_OCSP_URL.as_bytes()));
        write_tlv(TAG_SEQUENCE, &write_tlv(TAG_SEQUENCE, &description))
    }

    fn common_name(cn: &str) -> rcgen::DistinguishedName {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, cn);
        dn
    }

    /// A chain the way `proxy.tls_cert_file` holds one.
    struct TestChain {
        /// Leaf, decoy, and issuer concatenated, leaf first.
        pem: Vec<u8>,
        /// DER of the certificate that actually signed the leaf.
        issuer_der: Vec<u8>,
        /// DER of an unrelated certificate sitting between the two.
        decoy_der: Vec<u8>,
    }

    /// Build that chain, decoy and all.
    ///
    /// The decoy sits second on purpose. A stapler that reached for the
    /// next certificate in the file rather than for the one whose subject
    /// matches the leaf's issuer would hash the decoy's public key, and
    /// every request it built would name a certificate no responder has
    /// ever issued.
    fn signed_chain() -> TestChain {
        let issuer_key = rcgen::KeyPair::generate().expect("issuer key");
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("issuer params");
        issuer_params.distinguished_name = common_name("sbproxy ocsp test issuer");
        let issuer = issuer_params
            .self_signed(&issuer_key)
            .expect("issuer is self signed");

        let decoy_key = rcgen::KeyPair::generate().expect("decoy key");
        let mut decoy_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("decoy params");
        decoy_params.distinguished_name = common_name("sbproxy ocsp test decoy");
        let decoy = decoy_params
            .self_signed(&decoy_key)
            .expect("decoy is self signed");

        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let mut leaf_params = rcgen::CertificateParams::new(vec!["leaf.test.invalid".to_string()])
            .expect("leaf params");
        leaf_params.distinguished_name = common_name("sbproxy ocsp test leaf");
        leaf_params.serial_number = Some(rcgen::SerialNumber::from_slice(TEST_SERIAL));
        leaf_params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                // id-pe-authorityInfoAccess, 1.3.6.1.5.5.7.1.1.
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                aia_extension_der(),
            ));
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer, &issuer_key)
            .expect("leaf is signed by the issuer");

        TestChain {
            pem: format!("{}{}{}", leaf.pem(), decoy.pem(), issuer.pem()).into_bytes(),
            issuer_der: issuer.der().to_vec(),
            decoy_der: decoy.der().to_vec(),
        }
    }

    /// The first `CERTIFICATE` block of `pem`, so a chain can be cut down
    /// to the leaf a misconfigured deployment would have written.
    fn first_pem_block(pem: &[u8]) -> Vec<u8> {
        const END: &str = "-----END CERTIFICATE-----";
        let text = String::from_utf8_lossy(pem);
        match text.find(END) {
            Some(at) => text[..at + END.len()].as_bytes().to_vec(),
            None => Vec::new(),
        }
    }

    #[test]
    fn write_tlv_emits_the_short_and_long_definite_forms() {
        assert_eq!(write_tlv(TAG_NULL, &[]), vec![0x05, 0x00]);
        assert_eq!(
            write_tlv(TAG_OID, ID_SHA1),
            vec![0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A]
        );

        // 127 is the last length the short form holds.
        let short = write_tlv(TAG_OCTET_STRING, &[0xAA; 127]);
        assert_eq!(&short[..2], &[0x04, 0x7F]);

        // 128 is the first that needs the long form, and one octet holds it.
        let long = write_tlv(TAG_OCTET_STRING, &[0xAA; 128]);
        assert_eq!(&long[..3], &[0x04, 0x81, 0x80]);

        // Two octets, with no leading zero: DER wants the shortest form,
        // and `read_tlv` refuses anything else.
        let longer = write_tlv(TAG_OCTET_STRING, &[0xAA; 300]);
        assert_eq!(&longer[..4], &[0x04, 0x82, 0x01, 0x2C]);

        for contents in [vec![], vec![0xAA; 127], vec![0xAA; 128], vec![0xAA; 300]] {
            let encoded = write_tlv(TAG_OCTET_STRING, &contents);
            let (tag, decoded, rest) =
                read_tlv(&encoded).expect("what write_tlv writes is DER read_tlv accepts");
            assert_eq!(tag, TAG_OCTET_STRING);
            assert_eq!(decoded, contents.as_slice());
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn a_cert_id_round_trips_and_tolerates_absent_null_parameters() {
        let cert_id = test_cert_id(0x11);
        assert_eq!(
            CertId::from_der(&cert_id.to_der()).expect("what to_der writes, from_der reads"),
            cert_id
        );

        // Some responders omit the optional SHA-1 NULL parameters, which
        // RFC 3279 §2.1 allows. The same CertID has to decode either way:
        // a matcher comparing raw DER would call this a different
        // certificate and refuse a perfectly good response.
        let mut absent = write_tlv(TAG_SEQUENCE, &write_tlv(TAG_OID, ID_SHA1));
        absent.extend_from_slice(&write_tlv(TAG_OCTET_STRING, &cert_id.issuer_name_hash));
        absent.extend_from_slice(&write_tlv(TAG_OCTET_STRING, &cert_id.issuer_key_hash));
        absent.extend_from_slice(&write_tlv(TAG_INTEGER, &cert_id.serial));
        assert_eq!(
            CertId::from_der(&write_tlv(TAG_SEQUENCE, &absent))
                .expect("absent parameters still means SHA-1"),
            cert_id
        );

        // A stronger hash is not a closer match, it is a different
        // question, and answering a question nobody asked is the thing
        // this whole path exists to refuse.
        const ID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let mut other = write_tlv(TAG_SEQUENCE, &write_tlv(TAG_OID, ID_SHA256));
        other.extend_from_slice(&write_tlv(TAG_OCTET_STRING, &cert_id.issuer_name_hash));
        other.extend_from_slice(&write_tlv(TAG_OCTET_STRING, &cert_id.issuer_key_hash));
        other.extend_from_slice(&write_tlv(TAG_INTEGER, &cert_id.serial));
        CertId::from_der(&write_tlv(TAG_SEQUENCE, &other))
            .expect_err("a CertID under another hash is not the CertID that was sent");
    }

    #[test]
    fn a_request_names_the_leaf_under_its_own_issuer() {
        use x509_parser::certificate::X509Certificate;
        use x509_parser::prelude::FromDer as _;

        let chain = signed_chain();
        let target = ocsp_target(&chain.pem).expect("a full chain with an AIA URL is askable");

        assert_eq!(target.url, TEST_OCSP_URL);

        let (_, issuer) = X509Certificate::from_der(&chain.issuer_der).expect("issuer parses");
        let (_, decoy) = X509Certificate::from_der(&chain.decoy_der).expect("decoy parses");

        // The code hashes the leaf's `issuer` field. This hashes the
        // issuing certificate's `subject` field. Those are different
        // fields of different certificates that DER requires to be
        // byte-identical, so agreeing here rules out hashing the leaf's
        // own subject and rules out hashing the wrong certificate.
        assert_eq!(
            target.cert_id.issuer_name_hash,
            sha1(issuer.subject().as_raw()),
            "issuerNameHash has to be over the issuing CA's name"
        );
        assert_eq!(target.cert_id.issuer_name_hash.len(), 20);

        assert_eq!(
            target.cert_id.issuer_key_hash,
            sha1(issuer.public_key().subject_public_key.data.as_ref()),
            "issuerKeyHash has to be over the issuing CA's public key"
        );
        assert_eq!(target.cert_id.issuer_key_hash.len(), 20);
        assert_ne!(
            target.cert_id.issuer_key_hash,
            sha1(decoy.public_key().subject_public_key.data.as_ref()),
            "the second certificate in the file is not the issuer, and hashing it \
             would name a certificate no responder has ever issued"
        );

        assert_eq!(
            target.cert_id.serial, TEST_SERIAL,
            "the serial has to survive the round trip through DER unchanged"
        );
    }

    #[test]
    fn the_request_is_the_nested_ocsprequest_rfc_6960_defines() {
        let cert_id = test_cert_id(0x11);
        let request = ocsp_request_der(&cert_id);

        // OCSPRequest -> tbsRequest -> requestList -> Request -> reqCert.
        // Five levels, because `Request` wraps the CertID rather than
        // being it: RFC 6960 gives Request a singleRequestExtensions
        // sibling. Stopping at Request hands `CertId::from_der` a
        // SEQUENCE whose first element is the CertID, and it reports the
        // CertID's AlgorithmIdentifier where it wanted that identifier's
        // OID, which reads like an encoder bug and is not one.
        let (tbs, rest) = take_tlv(&request, TAG_SEQUENCE, "OCSPRequest").expect("OCSPRequest");
        assert!(rest.is_empty(), "one DER value and nothing after it");
        let (request_list, rest) = take_tlv(tbs, TAG_SEQUENCE, "tbsRequest").expect("tbsRequest");
        assert!(rest.is_empty(), "no requestorName, no requestExtensions");
        let (requests, rest) =
            take_tlv(request_list, TAG_SEQUENCE, "requestList").expect("requestList");
        assert!(rest.is_empty(), "the requestList is the last field");
        let (single, rest) = take_tlv(requests, TAG_SEQUENCE, "Request").expect("Request");
        assert!(rest.is_empty(), "exactly one Request in the list");
        let (req_cert, rest) = take_tlv_raw(single, TAG_SEQUENCE, "reqCert").expect("reqCert");
        assert!(rest.is_empty(), "no singleRequestExtensions");

        assert_eq!(
            CertId::from_der(req_cert).expect("reqCert is a CertID"),
            cert_id,
            "what goes on the wire has to be the CertID that was built"
        );

        // `version` is DEFAULT v1 and DER omits a field sitting at its
        // default, so no context tag appears anywhere. None of this
        // fixture's own bytes is 0xA0, so the scan means what it says.
        assert!(
            !request.contains(&TAG_CONTEXT_0),
            "no optional field is written, so no [0] appears: {request:02X?}"
        );
    }

    #[test]
    fn a_leaf_with_no_issuer_in_the_file_cannot_be_asked_about() {
        let chain = signed_chain();
        let leaf_only = first_pem_block(&chain.pem);

        let err = ocsp_target(&leaf_only)
            .expect_err("with no issuer there is no public key to hash and so no CertID");
        let message = format!("{err:#}");
        assert!(
            message.contains("full chain"),
            "the refusal has to tell an operator what to fix, got {message}"
        );
        assert_eq!(
            classify_fetch_error(&err),
            "parse_error",
            "a chain file missing its issuer is a configuration fault rather than a \
             dead responder: {message}"
        );
    }

    #[test]
    fn a_non_200_status_is_refused_and_graded_http_error() {
        ocsp_http_status(reqwest::StatusCode::OK).expect("a 200 is what carries an OCSPResponse");

        for status in [
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::NOT_FOUND,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let err = ocsp_http_status(status)
                .expect_err("a body that arrived with an error status is not a response");
            let message = format!("{err:#}");
            assert!(
                message.contains(status.as_str()),
                "the log has to name the status, got {message}"
            );
            assert_eq!(
                classify_fetch_error(&err),
                "http_error",
                "a refused status is a transport outcome, not a parse failure: {message}"
            );
        }
    }

    #[test]
    fn a_response_about_the_requested_certificate_is_accepted() {
        let asked = test_cert_id(0x11);
        let fetched = FetchedResponse {
            bytes: ocsp_response_about(std::slice::from_ref(&asked)),
            requested: asked,
        };
        accept_response(&fetched)
            .expect("a response about the certificate that was asked about is stapleable");
    }

    #[test]
    fn a_response_about_another_certificate_is_refused() {
        let asked = test_cert_id(0x11);

        let mut wrong_serial = asked.clone();
        wrong_serial.serial = vec![0x77, 0x77];
        let mut wrong_key = asked.clone();
        wrong_key.issuer_key_hash = vec![0x99; 20];
        let mut wrong_name = asked.clone();
        wrong_name.issuer_name_hash = vec![0x99; 20];

        for (field, answered) in [
            ("serialNumber", wrong_serial),
            ("issuerKeyHash", wrong_key),
            ("issuerNameHash", wrong_name),
        ] {
            let fetched = FetchedResponse {
                bytes: ocsp_response_about(&[answered]),
                requested: asked.clone(),
            };

            // The envelope check has nothing to object to. Substituting a
            // certificate does not make a response malformed, which is
            // why the CertID match is the check that carries this.
            assert!(
                stapleable_ocsp_response(&fetched.bytes).is_ok(),
                "the {field} substitution is still a well-formed successful basic response"
            );

            let err = accept_response(&fetched)
                .expect_err("a good response about a different certificate is not stapleable");
            assert!(
                format!("{err:#}").contains("none of them carries the CertID"),
                "a substituted {field} has to be refused as an answer about something \
                 else, got {err:#}"
            );
        }
    }

    #[test]
    fn a_response_with_no_single_response_answers_about_nothing() {
        let fetched = FetchedResponse {
            bytes: ocsp_response_about(&[]),
            requested: test_cert_id(0x11),
        };
        let err = accept_response(&fetched)
            .expect_err("an empty responses list is an answer about no certificate");
        assert!(
            format!("{err:#}").contains("answered about nothing"),
            "got {err:#}"
        );
    }

    #[test]
    fn grade_fetch_refuses_a_response_about_another_certificate_as_unknown_status() {
        let asked = test_cert_id(0x11);
        let mut answered = asked.clone();
        answered.serial = vec![0x77, 0x77];

        let (label, outcome) = grade_fetch(Ok(FetchedResponse {
            bytes: ocsp_response_about(&[answered]),
            requested: asked,
        }));
        assert_eq!(label, "unknown_status");
        assert!(
            outcome.is_err(),
            "a response about another certificate must not reach a CertifiedKey"
        );
    }
}

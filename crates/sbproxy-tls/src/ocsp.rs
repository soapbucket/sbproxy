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
//! # Why a fetch can succeed and still yield nothing to staple
//!
//! The fetch issues a bare `GET` against the responder URL rather than the
//! RFC 6960 §A.1 request, which carries a base64url-encoded `OCSPRequest`
//! naming the certificate as a path component. A responder handed no
//! request cannot answer for a certificate it was never told about, so it
//! replies with `malformedRequest`, or with an HTTP error page, and
//! `reqwest` reports both as a successful transfer. Those bytes are not a
//! staple, and `grade_fetch` refuses them.

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
    /// The responder URL is extracted from the certificate's Authority
    /// Information Access (AIA) extension.  The request is a simple HTTP GET
    /// (RFC 6960 §A.1 "GET method") using the pre-encoded issuer + serial
    /// path component.
    ///
    /// Returns the raw DER-encoded OCSP response bytes on success.
    ///
    /// Success here means the responder answered *and* what it answered
    /// with is a successful basic OCSP response. Reaching the responder is
    /// not enough: `reqwest` reports a 4xx as a completed transfer, so an
    /// error page and a `malformedRequest` response both arrive as bytes,
    /// and both are refused with the `unknown_status` outcome rather than
    /// returned for stapling. See the module docs for why that case is the
    /// common one today.
    pub async fn fetch_ocsp_response(cert_pem: &[u8]) -> Result<Vec<u8>> {
        let (result_label, outcome) = grade_fetch(Self::fetch_ocsp_response_inner(cert_pem).await);
        sbproxy_observe::metrics::record_ocsp_fetch(result_label);
        outcome
    }

    async fn fetch_ocsp_response_inner(cert_pem: &[u8]) -> Result<Vec<u8>> {
        use rustls::pki_types::{pem::PemObject as _, CertificateDer};
        use x509_parser::prelude::*;

        // --- Parse the leaf certificate ---
        let der_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .filter_map(|r| r.ok())
            .collect();
        let der = der_certs.first().context("no certificate found in PEM")?;

        let (_, cert) =
            X509Certificate::from_der(der.as_ref()).context("failed to parse certificate DER")?;

        // --- Extract OCSP responder URL from AIA extension ---
        let ocsp_url = extract_ocsp_url(&cert)
            .context("certificate has no OCSP responder URL in AIA extension")?;

        info!(ocsp_url = %ocsp_url, "fetching OCSP response");

        // --- Fetch via HTTP GET ---
        // RFC 6960 §A.1: the request URL is just the responder URL for a GET
        // with a base64url-encoded request appended as a path component.
        // For simplicity we fetch the base URL; production code would encode
        // the full OCSPRequest per RFC 5019.
        let response_bytes = reqwest::get(&ocsp_url)
            .await
            .with_context(|| format!("GET {ocsp_url}"))?
            .bytes()
            .await
            .context("reading OCSP response body")?
            .to_vec();

        Ok(response_bytes)
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
/// pure function of the bytes, and it is the half that can hurt an
/// operator, so it is the half worth pinning in a unit test.
fn grade_fetch(fetched: Result<Vec<u8>>) -> (&'static str, Result<Vec<u8>>) {
    match fetched {
        Ok(bytes) => match stapleable_ocsp_response(&bytes) {
            Ok(()) => ("ok", Ok(bytes)),
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

/// DER encoding of the `id-pkix-ocsp-basic` OID, `1.3.6.1.5.5.7.48.1.1`,
/// contents only. RFC 6960 §4.2.1 defines it as the one `responseType` a
/// responder must produce and a client must understand.
const ID_PKIX_OCSP_BASIC: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

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
        let (label, outcome) = grade_fetch(Ok(b"400 Bad Request".to_vec()));
        assert_eq!(label, "unknown_status");
        assert!(
            outcome.is_err(),
            "bytes that are not an OCSP response must not reach a CertifiedKey"
        );
    }

    #[test]
    fn grade_fetch_passes_a_real_response_through_as_ok() {
        let bytes = ocsp_response(0, true);
        let (label, outcome) = grade_fetch(Ok(bytes.clone()));
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
}

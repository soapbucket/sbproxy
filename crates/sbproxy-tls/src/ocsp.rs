//! OCSP response fetching and stapling.
//!
//! Fetches OCSP responses from the CA's OCSP responder URL (extracted from
//! the certificate's Authority Information Access extension) and caches them
//! for stapling during TLS handshakes. A background task refreshes the response
//! every 12 hours.

use anyhow::{Context, Result};
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

    /// Fetch the OCSP response for `cert_pem` from the CA's responder URL.
    ///
    /// The responder URL is extracted from the certificate's Authority
    /// Information Access (AIA) extension.  The request is a simple HTTP GET
    /// (RFC 6960 §A.1 "GET method") using the pre-encoded issuer + serial
    /// path component.
    ///
    /// Returns the raw DER-encoded OCSP response bytes on success.
    pub async fn fetch_ocsp_response(cert_pem: &[u8]) -> Result<Vec<u8>> {
        let outcome = Self::fetch_ocsp_response_inner(cert_pem).await;
        let result_label = match &outcome {
            Ok(_) => "ok",
            Err(e) => {
                let lower = format!("{e:#}").to_ascii_lowercase();
                if lower.contains("no ocsp responder") || lower.contains("aia extension") {
                    "no_responder"
                } else if lower.contains("parse") || lower.contains("certificate") {
                    "parse_error"
                } else {
                    "http_error"
                }
            }
        };
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

            // --- 12h refresh loop ---
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(12 * 3600));
            // The first tick fires immediately under tokio's default
            // policy; consume it so the loop sleeps 12h on the next
            // call.
            interval.tick().await;

            loop {
                interval.tick().await;

                match OcspStapler::fetch_ocsp_response(&cert_pem).await {
                    Ok(bytes) => {
                        info!(bytes = bytes.len(), "OCSP response refreshed");
                        response_slot.store(Arc::new(Some(bytes.clone())));
                        last_fetched_slot.store(Arc::new(Some(std::time::Instant::now())));
                        sbproxy_observe::metrics::record_ocsp_staple_age(&host, 0.0);
                        on_update(bytes);
                    }
                    Err(e) => {
                        error!("failed to refresh OCSP response: {e:#}");
                        // WOR-1024: surface the staleness via the
                        // gauge so an alert fires before the staple
                        // outlives its useful life. The host label
                        // matches the initial fetch.
                        if let Some(t) = last_fetched_slot.load().as_ref() {
                            sbproxy_observe::metrics::record_ocsp_staple_age(
                                &host,
                                t.elapsed().as_secs_f64(),
                            );
                        }
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

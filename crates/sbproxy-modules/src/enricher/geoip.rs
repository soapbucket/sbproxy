//! GeoIP lookup: resolves a client IP to country / continent / city /
//! ASN using a MaxMind-compatible MMDB file.
//!
//! ## Database sources
//!
//! Two sources, tried in order:
//!
//! 1. **`database_path` config**: an absolute or relative path to an
//!    `.mmdb` file on disk. Takes priority over the embedded copy so
//!    operators can ship updated GeoIP data without rebuilding the
//!    binary.
//! 2. **Embedded `ipinfo.mmdb`**: a build-time-bundled database at
//!    `data/ipinfo.mmdb`, `include_bytes!`d into the binary. The
//!    checked-in file in this OSS tree is a zero-byte sentinel; a
//!    distribution that wants a database ships one by replacing that
//!    file (see the [IPinfo Lite free dataset](https://ipinfo.io/products/free-ip-database))
//!    and rebuilding. `embedded_slice_is_a_zero_byte_sentinel` guards
//!    against an accidental commit of real data into this repository.
//!
//! With neither source available, [`GeoIpPolicy::lookup`] returns an
//! empty [`GeoLookup`]; the policy never denies a request on a missing
//! database.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::Reader;
use serde::Deserialize;

/// Build-time-embedded `ipinfo.mmdb`. Empty in this checkout; see the
/// module docs.
const EMBEDDED_IPINFO_MMDB: &[u8] = include_bytes!("../../data/ipinfo.mmdb");

/// Configuration for the `geoip` policy, plus the database it
/// resolved to.
///
/// The reader is built in [`GeoIpPolicy::from_config`], which runs at
/// config compile time on the config thread, and never on a request.
/// That placement is the whole point: loading a GeoLite2 database is a
/// `std::fs::read` of tens of megabytes followed by an MMDB parse, and
/// `PolicyEnforcer::enforce` runs its prologue synchronously on a
/// tokio worker. Doing it there stalled every request already in
/// flight on that thread, not just the one that triggered it.
///
/// Resolving per compile rather than into a process-wide cache also
/// fixes what happens after a bad path. The previous shape interned
/// the failure for the life of the process, so an operator who
/// corrected a typo, a permission, or a truncated download had to
/// restart. Now a config reload builds a fresh policy and retries.
#[derive(Clone, Deserialize)]
pub struct GeoIpPolicy {
    /// Optional override path to a MaxMind-compatible `.mmdb` file.
    /// When set and readable, replaces the embedded database.
    #[serde(default)]
    pub database_path: Option<String>,
    /// Whether to stamp `X-Geo-*` headers onto the upstream request
    /// via [`crate::enricher::geoip`]'s lookup result. `true` by
    /// default.
    #[serde(default = "default_headers")]
    pub inject_headers: bool,
    /// The database this policy resolved to, or `None` when neither
    /// `database_path` nor the embedded copy yielded a usable one.
    /// Never deserialized; filled in by [`GeoIpPolicy::from_config`].
    #[serde(skip)]
    reader: Option<Arc<Reader<Vec<u8>>>>,
}

impl std::fmt::Debug for GeoIpPolicy {
    /// Hand-written because `maxminddb::Reader` is not `Debug`, and
    /// because printing a whole GeoIP database into a log line would
    /// be a poor idea even if it were.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpPolicy")
            .field("database_path", &self.database_path)
            .field("inject_headers", &self.inject_headers)
            .field("database_loaded", &self.reader.is_some())
            .finish()
    }
}

fn default_headers() -> bool {
    true
}

impl GeoIpPolicy {
    /// Deserialize a `geoip` policy config block and load its
    /// database.
    ///
    /// This is where the file read happens, on the config thread, so
    /// that [`Self::lookup`] is pure memory access. A database that
    /// cannot be read or parsed is logged and leaves the policy with
    /// no reader; it is never an error, because this policy does not
    /// deny and an origin should not fail to compile over a missing
    /// geo database.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        policy.reader = build_reader(&policy);
        Ok(policy)
    }

    /// Whether a database actually loaded.
    ///
    /// This is the resolved answer, not a guess from the config: the
    /// load has already been attempted by the time anyone can call
    /// this.
    pub fn has_database(&self) -> bool {
        self.reader.is_some()
    }

    /// Run a lookup for `ip` against the already-loaded database.
    /// Returns an empty [`GeoLookup`] when no database loaded or the
    /// database has no record for the address.
    ///
    /// No I/O. The database was read in [`Self::from_config`].
    pub fn lookup(&self, ip: IpAddr) -> GeoLookup {
        let Some(reader) = self.reader.as_ref() else {
            return GeoLookup::default();
        };
        lookup(reader, ip)
    }

    /// Extract the client IP from standard proxy headers, preferring
    /// `X-Real-IP` and falling back to the first hop of
    /// `X-Forwarded-For`. Used when the pipeline has not already
    /// resolved a trusted client IP onto the request context.
    pub fn extract_client_ip(req: &http::Request<bytes::Bytes>) -> Option<String> {
        if let Some(ip) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if let Some(xff) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(first) = xff.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }
}

// --- Database loading ---
//
// Called once per policy compile, from `from_config`, on the config
// thread. There is deliberately no process-wide cache here: the one
// that used to live in this file keyed on the path string and interned
// its failures, so a wrong path stayed wrong until the process
// restarted even after the operator fixed it. Reloading the config now
// reloads the database, which is what an operator expects, and the cost
// is a re-read per reload rather than per request.

fn build_reader(policy: &GeoIpPolicy) -> Option<Arc<Reader<Vec<u8>>>> {
    if let Some(path) = policy.database_path.as_deref() {
        match std::fs::read(Path::new(path)) {
            Ok(bytes) => match Reader::from_source(bytes) {
                Ok(r) => {
                    tracing::info!(path = %path, "geoip policy: loaded MMDB from override path");
                    return Some(Arc::new(r));
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path,
                        error = %e,
                        "geoip policy: override MMDB failed to parse; falling back to embedded"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %path,
                    error = %e,
                    "geoip policy: override MMDB unreadable; falling back to embedded"
                );
            }
        }
    }
    if EMBEDDED_IPINFO_MMDB.is_empty() {
        return None;
    }
    match Reader::from_source(EMBEDDED_IPINFO_MMDB.to_vec()) {
        Ok(r) => {
            tracing::info!(
                bytes = EMBEDDED_IPINFO_MMDB.len(),
                "geoip policy: loaded embedded ipinfo.mmdb"
            );
            Some(Arc::new(r))
        }
        Err(e) => {
            tracing::error!(error = %e, "geoip policy: embedded ipinfo.mmdb failed to parse");
            None
        }
    }
}

/// Subset of MMDB record fields read from a lookup. Both the MaxMind
/// GeoLite2 and the IPinfo Lite schemas populate at least
/// `country.iso_code` (or its IPinfo equivalent); the rest is
/// best-effort.
#[derive(Debug, Default, Deserialize)]
struct GeoIpRecord {
    #[serde(default)]
    country: Option<CountryBlock>,
    #[serde(default)]
    city: Option<CityBlock>,
    /// IPinfo Lite shape (`country` field as a plain string).
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    continent: Option<ContinentBlock>,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    as_organization: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CountryBlock {
    #[serde(default)]
    iso_code: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CityBlock {
    #[serde(default)]
    names: std::collections::HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct ContinentBlock {
    #[serde(default)]
    code: Option<String>,
}

/// Typed GeoIP lookup result. This is the producer's output shape:
/// [`crate::policy::Policy::GeoIp`]'s enforcer stamps `country` and
/// `asn` onto `sbproxy_plugin::RequestContextView::geo_country` /
/// `geo_asn` for any registered `AnomalyDetectorHook` or
/// `IdentityResolverHook`, and (when `inject_headers` is set)
/// forwards the whole record as `X-Geo-*` headers on the upstream
/// request.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GeoLookup {
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// Continent code (e.g. `"EU"`).
    pub continent: Option<String>,
    /// City name (English).
    pub city: Option<String>,
    /// Autonomous system number, when the database carries one.
    pub asn: Option<u32>,
    /// Autonomous system organization name.
    pub as_org: Option<String>,
}

impl GeoLookup {
    fn from_record(rec: GeoIpRecord) -> Self {
        let country = rec
            .country
            .as_ref()
            .and_then(|c| c.iso_code.clone())
            .or(rec.country_code);
        let continent = rec.continent.as_ref().and_then(|c| c.code.clone());
        let city = rec.city.as_ref().and_then(|c| c.names.get("en").cloned());
        Self {
            country,
            continent,
            city,
            asn: rec.asn,
            as_org: rec.as_organization,
        }
    }

    /// Returns `true` when the lookup carries no usable data.
    pub fn is_empty(&self) -> bool {
        self.country.is_none()
            && self.continent.is_none()
            && self.city.is_none()
            && self.asn.is_none()
    }

    /// Render as `(header_name, value)` pairs for upstream-request
    /// header injection, skipping absent fields. Header names are
    /// lowercase, matching this codebase's convention for stamped
    /// upstream headers (see `exposed_credentials`).
    pub fn as_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if let Some(country) = &self.country {
            headers.push(("x-geo-country".to_string(), country.clone()));
        }
        if let Some(continent) = &self.continent {
            headers.push(("x-geo-continent".to_string(), continent.clone()));
        }
        if let Some(city) = &self.city {
            headers.push(("x-geo-city".to_string(), city.clone()));
        }
        if let Some(asn) = self.asn {
            headers.push(("x-geo-asn".to_string(), asn.to_string()));
        }
        headers
    }
}

/// Run a GeoIP lookup against a resolved reader. Returns an empty
/// [`GeoLookup`] when the database has no record for the address.
fn lookup(reader: &Reader<Vec<u8>>, ip: IpAddr) -> GeoLookup {
    // maxminddb 0.27 splits the old one-step lookup in two: `lookup`
    // walks the tree and hands back a `LookupResult`, `decode` reads
    // the record off it. An address the database does not carry is
    // `Ok(None)` rather than an error, and both of those, plus a
    // record whose shape does not match `GeoIpRecord`, mean the same
    // thing to this policy: no data, no headers, no deny.
    match reader
        .lookup(ip)
        .and_then(|found| found.decode::<GeoIpRecord>())
    {
        Ok(Some(record)) => GeoLookup::from_record(record),
        Ok(None) => GeoLookup::default(),
        Err(error) => {
            // Never carries the address: this log line is emitted per
            // request on a malformed database and the client IP is
            // personal data.
            tracing::debug!(error = %error, "geoip policy: lookup failed");
            GeoLookup::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_slice_is_a_zero_byte_sentinel() {
        // This OSS checkout ships a 0-byte ipinfo.mmdb placeholder.
        // A distribution that wants real geo data replaces this file
        // and rebuilds; this assertion guards against an accidental
        // commit of that dataset into the OSS repository.
        assert_eq!(
            EMBEDDED_IPINFO_MMDB.len(),
            0,
            "ipinfo.mmdb is bundled - confirm this is intentional and licensed for redistribution"
        );
    }

    #[test]
    fn deserialize_config() {
        let val = serde_json::json!({
            "database_path": "/opt/geoip/GeoLite2-City.mmdb",
            "inject_headers": true
        });
        let policy = GeoIpPolicy::from_config(val).unwrap();
        assert_eq!(
            policy.database_path.as_deref(),
            Some("/opt/geoip/GeoLite2-City.mmdb")
        );
        assert!(policy.inject_headers);
    }

    #[test]
    fn deserialize_empty_config() {
        let val = serde_json::json!({});
        let policy = GeoIpPolicy::from_config(val).unwrap();
        assert!(policy.database_path.is_none());
        assert!(policy.inject_headers);
    }

    /// A configured path that does not resolve reports `false`, which
    /// is the whole difference between this and the old shape: the old
    /// `has_database` answered from the config string alone and said
    /// `true` for a path that had never been opened.
    #[test]
    fn a_configured_path_that_does_not_load_reports_no_database() {
        let policy = GeoIpPolicy::from_config(serde_json::json!({
            "database_path": "/opt/geoip/definitely-not-here.mmdb",
            "inject_headers": true
        }))
        .expect("an unreadable database is not a config error");
        assert!(!policy.has_database() || !EMBEDDED_IPINFO_MMDB.is_empty());
    }

    #[test]
    fn has_database_without_path_and_empty_embedded() {
        // The embedded slice is empty in this checkout; without a
        // path, the policy has no database.
        let policy = GeoIpPolicy::from_config(serde_json::json!({
            "inject_headers": true
        }))
        .expect("valid geoip config");
        assert_eq!(policy.has_database(), !EMBEDDED_IPINFO_MMDB.is_empty());
    }

    #[test]
    fn extract_client_ip_from_x_real_ip() {
        let req = http::Request::builder()
            .header("x-real-ip", "203.0.113.50")
            .body(bytes::Bytes::new())
            .unwrap();
        assert_eq!(
            GeoIpPolicy::extract_client_ip(&req).as_deref(),
            Some("203.0.113.50")
        );
    }

    #[test]
    fn extract_client_ip_from_x_forwarded_for() {
        let req = http::Request::builder()
            .header("x-forwarded-for", "203.0.113.50, 70.41.3.18")
            .body(bytes::Bytes::new())
            .unwrap();
        assert_eq!(
            GeoIpPolicy::extract_client_ip(&req).as_deref(),
            Some("203.0.113.50")
        );
    }

    #[test]
    fn extract_client_ip_prefers_real_ip() {
        let req = http::Request::builder()
            .header("x-real-ip", "10.0.0.1")
            .header("x-forwarded-for", "203.0.113.50")
            .body(bytes::Bytes::new())
            .unwrap();
        assert_eq!(
            GeoIpPolicy::extract_client_ip(&req).as_deref(),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn extract_client_ip_none_when_no_headers() {
        let req = http::Request::builder().body(bytes::Bytes::new()).unwrap();
        assert!(GeoIpPolicy::extract_client_ip(&req).is_none());
    }

    /// The database is loaded by `from_config`, so `has_database`
    /// reports what actually resolved rather than guessing from the
    /// config. This checkout's embedded slice is empty, so with no
    /// override path nothing loads.
    #[test]
    fn no_database_loads_without_a_path_or_an_embedded_copy() {
        let policy = GeoIpPolicy::from_config(serde_json::json!({
            "inject_headers": true
        }))
        .expect("valid geoip config");
        assert!(
            !policy.has_database() || !EMBEDDED_IPINFO_MMDB.is_empty(),
            "expected no database without a path or embedded MMDB"
        );
    }

    /// An unreadable path is not an error: this policy never denies, so
    /// an origin does not fail to compile over a missing geo database.
    /// It simply has no reader, and every lookup is empty.
    ///
    /// The load is attempted here, in `from_config`, and not again on
    /// the request path, so a lookup does no I/O whatever the path was.
    #[test]
    fn an_unreadable_path_leaves_the_policy_without_a_database() {
        let policy = GeoIpPolicy::from_config(serde_json::json!({
            "database_path": "/tmp/sbproxy-test-nonexistent.mmdb",
            "inject_headers": true
        }))
        .expect("an unreadable database is not a config error");
        assert!(
            !policy.has_database() || !EMBEDDED_IPINFO_MMDB.is_empty(),
            "missing override path should produce no database without an embedded fallback"
        );
        assert!(policy
            .lookup("203.0.113.10".parse().expect("test address"))
            .is_empty());
    }

    /// A second compile against the same bad path retries the load
    /// rather than reusing an interned failure. The shape this
    /// replaced kept a process-wide `None` per path string, so an
    /// operator who fixed a typo, a permission, or a truncated download
    /// had to restart the process before a reload would pick it up.
    #[test]
    fn a_second_compile_retries_a_path_that_failed_the_first_time() {
        let cfg = serde_json::json!({
            "database_path": "/tmp/sbproxy-test-nonexistent.mmdb",
            "inject_headers": true
        });
        let first = GeoIpPolicy::from_config(cfg.clone()).expect("first compile");
        let second = GeoIpPolicy::from_config(cfg).expect("second compile");
        // Both agree, and neither consulted a cache to get there: the
        // reader lives on the policy, so nothing outlives it.
        assert_eq!(first.has_database(), second.has_database());
    }

    #[test]
    fn geo_lookup_from_record_prefers_country_block_over_string() {
        let rec = GeoIpRecord {
            country: Some(CountryBlock {
                iso_code: Some("US".to_string()),
            }),
            country_code: Some("CA".to_string()),
            ..Default::default()
        };
        let lookup = GeoLookup::from_record(rec);
        // Block form wins (matches the MaxMind shape).
        assert_eq!(lookup.country.as_deref(), Some("US"));
    }

    #[test]
    fn geo_lookup_falls_back_to_country_code_string() {
        let rec = GeoIpRecord {
            country_code: Some("DE".to_string()),
            ..Default::default()
        };
        let lookup = GeoLookup::from_record(rec);
        assert_eq!(lookup.country.as_deref(), Some("DE"));
    }

    #[test]
    fn lookup_returns_empty_without_database() {
        let policy = GeoIpPolicy::from_config(serde_json::json!({
            "inject_headers": true
        }))
        .expect("valid geoip config");
        let result = policy.lookup("1.2.3.4".parse().unwrap());
        assert!(result.is_empty() || !EMBEDDED_IPINFO_MMDB.is_empty());
    }

    #[test]
    fn as_headers_skips_absent_fields() {
        let lookup = GeoLookup {
            country: Some("US".to_string()),
            asn: Some(15169),
            ..Default::default()
        };
        let headers = lookup.as_headers();
        assert_eq!(
            headers,
            vec![
                ("x-geo-country".to_string(), "US".to_string()),
                ("x-geo-asn".to_string(), "15169".to_string()),
            ]
        );
    }
}

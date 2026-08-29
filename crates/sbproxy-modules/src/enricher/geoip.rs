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
use std::sync::{Arc, OnceLock};

use maxminddb::Reader;
use serde::Deserialize;

/// Build-time-embedded `ipinfo.mmdb`. Empty in this checkout; see the
/// module docs.
const EMBEDDED_IPINFO_MMDB: &[u8] = include_bytes!("../../data/ipinfo.mmdb");

/// Configuration for the `geoip` policy.
#[derive(Debug, Clone, Deserialize)]
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
}

fn default_headers() -> bool {
    true
}

impl GeoIpPolicy {
    /// Deserialize a `geoip` policy config block.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Check whether the policy has a usable database (override path
    /// or non-empty embedded slice). Does not attempt to parse it;
    /// [`Self::lookup`] does that on demand.
    pub fn has_database(&self) -> bool {
        self.database_path
            .as_ref()
            .map(|p| !p.is_empty())
            .unwrap_or(false)
            || !EMBEDDED_IPINFO_MMDB.is_empty()
    }

    /// Run a lookup for `ip`, honoring `database_path` then the
    /// embedded database. Returns an empty [`GeoLookup`] when no
    /// database is available or the database has no record for the
    /// address.
    pub fn lookup(&self, ip: IpAddr) -> GeoLookup {
        let Some(reader) = resolve_reader(self) else {
            return GeoLookup::default();
        };
        lookup(&reader, ip)
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

// --- Lazy reader cache ---

/// Cached MaxMind reader handle. `None` means a previous attempt for
/// the same source could not load the database and should not be
/// retried.
type CachedReader = Option<Arc<Reader<Vec<u8>>>>;

/// Process-wide reader cache keyed by source path (or the literal
/// `"<embedded>"` token). The reader is expensive to build but cheap
/// to share; requests get an `Arc` clone.
static READER_CACHE: OnceLock<dashmap::DashMap<String, CachedReader>> = OnceLock::new();

fn cache() -> &'static dashmap::DashMap<String, CachedReader> {
    READER_CACHE.get_or_init(dashmap::DashMap::new)
}

/// Resolve a [`maxminddb::Reader`] for the given policy config,
/// honoring the override path then the embedded database. Returns
/// `None` when no usable database is available.
fn resolve_reader(policy: &GeoIpPolicy) -> Option<Arc<Reader<Vec<u8>>>> {
    let key = policy
        .database_path
        .clone()
        .unwrap_or_else(|| "<embedded>".to_string());
    let cache = cache();
    if let Some(entry) = cache.get(&key) {
        return entry.clone();
    }
    let reader = build_reader(policy);
    cache.insert(key, reader.clone());
    reader
}

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

    #[test]
    fn has_database_with_path() {
        let policy = GeoIpPolicy {
            database_path: Some("/opt/geoip/GeoLite2-City.mmdb".to_string()),
            inject_headers: true,
        };
        assert!(policy.has_database());
    }

    #[test]
    fn has_database_without_path_and_empty_embedded() {
        // The embedded slice is empty in this checkout; without a
        // path, the policy has no database.
        let policy = GeoIpPolicy {
            database_path: None,
            inject_headers: true,
        };
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

    #[test]
    fn resolve_reader_returns_none_when_no_db_available() {
        // This checkout's embedded slice is empty; with no override
        // path, resolve_reader must return None.
        let policy = GeoIpPolicy {
            database_path: None,
            inject_headers: true,
        };
        let reader = resolve_reader(&policy);
        assert!(
            reader.is_none() || !EMBEDDED_IPINFO_MMDB.is_empty(),
            "expected no reader without a path or embedded MMDB"
        );
    }

    #[test]
    fn resolve_reader_returns_none_for_unreadable_path() {
        let policy = GeoIpPolicy {
            database_path: Some("/tmp/sbproxy-test-nonexistent.mmdb".to_string()),
            inject_headers: true,
        };
        // With no embedded fallback, the missing path leaves us
        // empty-handed; with an embedded DB it falls through to it.
        let reader = resolve_reader(&policy);
        assert!(
            reader.is_none() || !EMBEDDED_IPINFO_MMDB.is_empty(),
            "missing override path should produce no reader without an embedded fallback"
        );
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
        let policy = GeoIpPolicy {
            database_path: None,
            inject_headers: true,
        };
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

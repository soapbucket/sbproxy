//! One DNS-pinned, no-redirect egress policy for OAuth security endpoints.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use sbproxy_security::ssrf::validate_dialable_addrs;

const DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a pinned client may be reused before its endpoint is
/// resolved and re-validated.
///
/// A pinned client is exactly as fresh as the resolution behind it, so
/// this is the window in which a legitimate DNS change is not seen and
/// also the window a rebind attempt would have to survive. Sixty
/// seconds is short enough that an operator moving an authorization
/// server sees the move inside a minute, and long enough that a burst
/// of `/token` requests shares one TLS handshake and one connection
/// pool instead of building a fresh TLS stack each time.
const CLIENT_TTL: Duration = Duration::from_secs(60);

/// Maximum distinct endpoints held. The keys come from operator config
/// plus one `jwks_uri` per configured authorization server, so this is
/// far above any real deployment; it is here so a misconfiguration
/// cannot grow the map without bound.
const CLIENT_CACHE_CAPACITY: usize = 64;

/// Cache key. `allow_insecure_loopback` is part of it because it
/// decides whether a plain-HTTP endpoint is permitted at all, so two
/// callers disagreeing about it must not share a client.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ClientKey {
    scheme: String,
    host: String,
    port: u16,
    allow_insecure_loopback: bool,
}

struct CachedClient {
    client: reqwest::Client,
    validated_at: Instant,
}

static CLIENT_CACHE: LazyLock<Mutex<HashMap<ClientKey, CachedClient>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Return a still-fresh pinned client for `key`, if one is held.
fn cached_client(key: &ClientKey) -> Option<reqwest::Client> {
    let mut cache = CLIENT_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    let entry = cache.get(key)?;
    if entry.validated_at.elapsed() < CLIENT_TTL {
        return Some(entry.client.clone());
    }
    cache.remove(key);
    None
}

/// Store a freshly validated client, dropping expired entries first and
/// refusing to grow past the capacity bound.
fn store_client(key: ClientKey, client: &reqwest::Client) {
    let mut cache = CLIENT_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    cache.retain(|_, entry| entry.validated_at.elapsed() < CLIENT_TTL);
    if cache.len() >= CLIENT_CACHE_CAPACITY && !cache.contains_key(&key) {
        // Full of live entries: serve this one without caching rather
        // than evicting somebody else's warm pool.
        return;
    }
    cache.insert(
        key,
        CachedClient {
            client: client.clone(),
            validated_at: Instant::now(),
        },
    );
}

/// Validate an OAuth endpoint, resolve it, reject special-use targets,
/// and return a client pinned to exactly those addresses. Plain HTTP is
/// accepted only for an explicit loopback development override.
///
/// The pinned client is cached for [`CLIENT_TTL`] and shared by every
/// caller dialing the same endpoint, so a burst of `/token` requests
/// reuses one TLS stack and one connection pool. Past the TTL the
/// endpoint is resolved and re-validated before a client is handed out
/// again: the cache never extends the life of a validation decision.
pub(crate) async fn endpoint_client(
    raw_url: &str,
    allow_insecure_loopback: bool,
) -> Result<(url::Url, reqwest::Client)> {
    let parsed = validate_endpoint_url(raw_url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("OAuth endpoint has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let port = parsed.port_or_known_default().ok_or_else(|| {
        anyhow!("OAuth endpoint scheme has no known port and no port was configured")
    })?;
    let key = ClientKey {
        scheme: parsed.scheme().to_string(),
        host: host.clone(),
        port,
        allow_insecure_loopback,
    };
    if let Some(client) = cached_client(&key) {
        return Ok((parsed, client));
    }
    let addresses = resolve(&host, port).await?;
    // Canonicalize before the loopback test for the same reason the
    // range check does: `::ffff:127.0.0.1` is loopback, and
    // `Ipv6Addr::is_loopback` says otherwise.
    let loopback_only = addresses
        .iter()
        .all(|address| sbproxy_security::ssrf::canonical_ip(address.ip()).is_loopback());
    if parsed.scheme() == "http" {
        if !allow_insecure_loopback || !loopback_only {
            bail!("OAuth endpoints require HTTPS; HTTP is allowed only for an explicit loopback development override");
        }
    } else if addresses
        .iter()
        .any(|address| is_disallowed_ip(address.ip()))
    {
        bail!("OAuth endpoint resolves to a private, loopback, link-local, or special-use address");
    }
    let resolver = Arc::new(PinnedResolver {
        host: host.clone(),
        addresses,
    });
    let client = sbproxy_httpkit::OutboundClientBuilder::new()
        .no_redirects()
        .into_inner()
        .dns_resolver(resolver)
        .build()
        .map_err(|error| anyhow!("OAuth egress client build failed: {error}"))?;
    store_client(key, &client);
    Ok((parsed, client))
}

pub(crate) fn validate_endpoint_url(raw_url: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(raw_url)
        .map_err(|_| anyhow!("OAuth endpoint must be an absolute HTTP(S) URL"))?;
    if !matches!(parsed.scheme(), "https" | "http")
        || !parsed.has_host()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("OAuth endpoint must be an absolute HTTP(S) URL without credentials, query, or fragment");
    }
    Ok(parsed)
}

async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let lookup = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| anyhow!("OAuth endpoint DNS lookup timed out"))?
        .map_err(|_| anyhow!("OAuth endpoint DNS lookup failed"))?;
    let addresses = lookup.collect::<Vec<_>>();
    if addresses.is_empty() {
        bail!("OAuth endpoint DNS lookup returned no addresses");
    }
    Ok(addresses)
}

/// Returns true when `ip` must not be dialed for an OAuth endpoint.
///
/// Delegates to the workspace's shared dial-time range check,
/// [`sbproxy_security::ssrf::validate_dialable_addrs`], which
/// canonicalizes IPv4-mapped IPv6 (`::ffff:a.b.c.d`) before testing.
/// One `jwks_uri` reaching this guard comes out of a fetched upstream
/// metadata document rather than the operator's config
/// (`as_metadata.rs`), so the v6-shaped spelling of a private address
/// is remote-controlled input here.
///
/// The port is irrelevant to a range test, so a placeholder is used.
fn is_disallowed_ip(ip: IpAddr) -> bool {
    validate_dialable_addrs(&[SocketAddr::new(ip, 0)]).is_err()
}

struct PinnedResolver {
    host: String,
    addresses: Vec<SocketAddr>,
}

impl reqwest::dns::Resolve for PinnedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        if name.as_str().eq_ignore_ascii_case(&self.host) {
            let addresses: reqwest::dns::Addrs = Box::new(self.addresses.clone().into_iter());
            Box::pin(std::future::ready(Ok(addresses)))
        } else {
            let error: Box<dyn std::error::Error + Send + Sync> =
                "DNS-pinned OAuth client refused a different hostname".into();
            Box::pin(std::future::ready(Err(error)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_private_https_and_public_http_targets() {
        assert!(endpoint_client("https://169.254.169.254/token", false)
            .await
            .is_err());
        assert!(endpoint_client("http://8.8.8.8/token", true).await.is_err());
    }

    #[tokio::test]
    async fn refuses_the_ipv4_mapped_ipv6_spelling_of_a_private_target() {
        // `::ffff:169.254.169.254` is the metadata endpoint written in
        // the v6 form. A dual-stack connect reaches it.
        for mapped in [
            "https://[::ffff:169.254.169.254]/token",
            "https://[::ffff:10.0.4.7]/token",
            "https://[::ffff:127.0.0.1]/token",
        ] {
            assert!(
                endpoint_client(mapped, false).await.is_err(),
                "{mapped} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn explicit_development_override_is_loopback_only() {
        assert!(endpoint_client("http://127.0.0.1:1/token", false)
            .await
            .is_err());
        assert!(endpoint_client("http://127.0.0.1:1/token", true)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn a_validated_endpoint_client_is_reused_within_the_ttl() {
        // Without the cache every `/token` request built a fresh TLS
        // stack and a fresh connection pool and did its own DNS
        // lookup, so no two token issuances ever shared a connection.
        let key = ClientKey {
            scheme: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1,
            allow_insecure_loopback: true,
        };
        assert!(cached_client(&key).is_none(), "nothing cached yet");
        endpoint_client("http://127.0.0.1:1/token", true)
            .await
            .expect("loopback override");
        assert!(
            cached_client(&key).is_some(),
            "a validated endpoint must be reusable"
        );
    }

    #[tokio::test]
    async fn a_refused_endpoint_is_never_cached() {
        assert!(endpoint_client("https://169.254.169.254/token", false)
            .await
            .is_err());
        let key = ClientKey {
            scheme: "https".to_string(),
            host: "169.254.169.254".to_string(),
            port: 443,
            allow_insecure_loopback: false,
        };
        assert!(
            cached_client(&key).is_none(),
            "a refusal must not leave a usable client behind"
        );
    }

    #[test]
    fn rejects_url_credentials_query_and_fragment() {
        for url in [
            "https://user:secret@example.com/token",
            "https://example.com/token?sig=secret",
            "https://example.com/token#fragment",
        ] {
            assert!(validate_endpoint_url(url).is_err(), "{url}");
        }
    }
}

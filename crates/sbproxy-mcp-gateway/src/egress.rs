//! One DNS-pinned, no-redirect egress policy for OAuth security endpoints.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};

const DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// Validate an OAuth endpoint, resolve it once, reject special-use targets,
/// and build a client pinned to exactly those addresses. Plain HTTP is
/// accepted only for an explicit loopback development override.
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
    let addresses = resolve(&host, port).await?;
    let loopback_only = addresses.iter().all(|address| address.ip().is_loopback());
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

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_unspecified()
                || address.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
                || octets[0] >= 240
        }
        IpAddr::V6(address) => {
            let first = address.segments()[0];
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
        }
    }
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
    async fn explicit_development_override_is_loopback_only() {
        assert!(endpoint_client("http://127.0.0.1:1/token", false)
            .await
            .is_err());
        assert!(endpoint_client("http://127.0.0.1:1/token", true)
            .await
            .is_ok());
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

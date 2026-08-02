//! DNS-pinned provider client construction and bounded JSON response reads.
//!
//! Shared code owns the outbound URL policy for every RAG provider: scheme
//! restrictions, userinfo and query and fragment rejection, SSRF validation
//! with resolved-address pinning, redirect refusal, timeouts, and the
//! response byte cap. Provider adapters only shape requests and parse
//! responses.

use std::net::SocketAddr;
use std::time::Duration;

use sbproxy_ai::rag_config::MAX_PROVIDER_RESPONSE_BYTES;
use sbproxy_httpkit::OutboundClientBuilder;
use sbproxy_security::{is_private_ip, validate_url_resolved};

use crate::{EmbeddingError, RagBuildError, VectorStoreError};

/// A non-secret transport-level failure from a provider HTTP exchange.
///
/// Variants intentionally carry no URL, header, body, or credential data.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHttpError {
    /// The complete send and body read did not finish in time.
    Timeout,
    /// The provider answered with a non-2xx status code.
    HttpStatus(u16),
    /// The response body exceeded the shared provider byte cap.
    ResponseTooLarge,
    /// The response body was not valid JSON.
    MalformedJson,
    /// The connection failed or was interrupted; the reason is a fixed
    /// non-secret label.
    Transport(&'static str),
}

impl From<ProviderHttpError> for EmbeddingError {
    fn from(error: ProviderHttpError) -> Self {
        match error {
            ProviderHttpError::Timeout => EmbeddingError::Timeout,
            ProviderHttpError::HttpStatus(status) => EmbeddingError::HttpStatus(status),
            ProviderHttpError::ResponseTooLarge => EmbeddingError::ResponseTooLarge,
            ProviderHttpError::MalformedJson => {
                EmbeddingError::MalformedResponse("response body is not valid json")
            }
            ProviderHttpError::Transport(reason) => EmbeddingError::MalformedResponse(reason),
        }
    }
}

impl From<ProviderHttpError> for VectorStoreError {
    fn from(error: ProviderHttpError) -> Self {
        match error {
            ProviderHttpError::Timeout => VectorStoreError::Timeout,
            ProviderHttpError::HttpStatus(status) => VectorStoreError::HttpStatus(status),
            ProviderHttpError::ResponseTooLarge => VectorStoreError::ResponseTooLarge,
            ProviderHttpError::MalformedJson => {
                VectorStoreError::MalformedResponse("response body is not valid json")
            }
            ProviderHttpError::Transport(reason) => VectorStoreError::MalformedResponse(reason),
        }
    }
}

/// Checks the provider URL shape without touching the network.
///
/// Only `http` and `https` are permitted. Userinfo, query strings, and
/// fragments are rejected so a credential cannot hide inside the
/// configured endpoint. The host must be present.
fn parse_provider_url(base_url: &str) -> Result<url::Url, RagBuildError> {
    let parsed = url::Url::parse(base_url)
        .map_err(|_| RagBuildError::InvalidConfig("provider url does not parse".to_owned()))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(RagBuildError::InvalidConfig(
            "provider url must use http or https".to_owned(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RagBuildError::InvalidConfig(
            "provider url must not contain userinfo".to_owned(),
        ));
    }
    if parsed.query().is_some() {
        return Err(RagBuildError::InvalidConfig(
            "provider url must not contain a query".to_owned(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(RagBuildError::InvalidConfig(
            "provider url must not contain a fragment".to_owned(),
        ));
    }
    if parsed.host_str().is_none() {
        return Err(RagBuildError::InvalidConfig(
            "provider url has no host".to_owned(),
        ));
    }
    // The effective port is carried by the URL itself; reqwest ignores the
    // port on pinned addresses and dials the URL port (or scheme default).
    let _effective_port = parsed.port_or_known_default();
    Ok(parsed)
}

/// Validates the provider URL shape only, for validation-time builds.
///
/// This performs no DNS resolution and no network I/O.
// Gated to its only callers, the feature-gated embedding and HTTP vector
// adapters, so a build with no provider feature carries no dead code.
// Extend the gate when a new feature-gated adapter adopts this helper.
#[cfg(any(
    feature = "embedding-openai",
    feature = "embedding-cohere",
    feature = "embedding-bedrock",
    feature = "embedding-vertex",
    feature = "vector-chroma",
    feature = "vector-pinecone",
    feature = "vector-qdrant",
    feature = "vector-weaviate"
))]
pub(crate) fn validate_provider_url_shape(base_url: &str) -> Result<(), RagBuildError> {
    parse_provider_url(base_url).map(|_| ())
}

/// Builds a redirect-free client without resolving or pinning the host.
///
/// Used for validation-mode construction and for an explicitly allowlisted
/// internal hostname that only resolves at dial time.
// Gated to its only callers, the feature-gated embedding and HTTP vector
// adapters, so a build with no provider feature carries no dead code.
// Extend the gate when a new feature-gated adapter adopts this helper.
#[cfg(any(
    feature = "embedding-openai",
    feature = "embedding-cohere",
    feature = "embedding-bedrock",
    feature = "embedding-vertex",
    feature = "vector-chroma",
    feature = "vector-pinecone",
    feature = "vector-qdrant",
    feature = "vector-weaviate"
))]
pub(crate) fn build_provider_client_unresolved(
    base_url: &str,
    timeout: Duration,
) -> Result<reqwest::Client, RagBuildError> {
    validate_provider_url_shape(base_url)?;
    finish_client(provider_client_builder(timeout))
}

/// Builds the pinned, redirect-free, bounded client for one provider endpoint.
///
/// The URL shape is checked first. The host is then validated through
/// `sbproxy_security::validate_url_resolved`; with `allow_private_url` the
/// exact host is passed as the allowlist, which is the only way a private,
/// loopback, link-local, metadata, CGNAT, or documentation address is
/// permitted. Every non-allowlisted resolved address is rechecked with the
/// SSRF private-IP check, and the validated addresses are pinned so the
/// dial cannot be redirected by a second DNS answer. An allowlisted
/// internal hostname that cannot resolve until dial time is permitted
/// unpinned, but only under the explicit private opt-in.
#[doc(hidden)]
pub fn build_provider_client(
    base_url: &str,
    allow_private_url: bool,
    timeout: Duration,
) -> Result<reqwest::Client, RagBuildError> {
    let parsed = parse_provider_url(base_url)?;
    let host = parsed
        .host_str()
        .expect("parse_provider_url guarantees a host")
        .to_owned();

    let allowlist: Vec<String> = if allow_private_url {
        vec![host.clone()]
    } else {
        Vec::new()
    };
    let resolved =
        validate_url_resolved(base_url, &allowlist).map_err(RagBuildError::InvalidConfig)?;
    if !resolved.allowlisted {
        for addr in &resolved.addrs {
            if is_private_ip(&addr.ip()) {
                return Err(RagBuildError::InvalidConfig(
                    "provider endpoint resolves to a private address; set allow_private_url to opt in"
                        .to_owned(),
                ));
            }
        }
    }
    if resolved.addrs.is_empty() {
        if !allow_private_url {
            return Err(RagBuildError::InvalidConfig(
                "provider endpoint resolved to no addresses".to_owned(),
            ));
        }
        return finish_client(provider_client_builder(timeout));
    }
    finish_client(
        provider_client_builder(timeout).resolve_to_addrs(&resolved.host, &resolved.addrs),
    )
}

/// Builds the pinned client from caller-supplied resolved addresses.
///
/// Test seam used by the outbound-policy contract tests to exercise the
/// pinning and private-address policy without live DNS. The URL shape
/// policy is identical to [`build_provider_client`]; without
/// `allow_private_url` every supplied address must be public.
#[doc(hidden)]
pub fn build_provider_client_with_resolved(
    base_url: &str,
    allow_private_url: bool,
    timeout: Duration,
    resolved: Vec<SocketAddr>,
) -> Result<reqwest::Client, RagBuildError> {
    let parsed = parse_provider_url(base_url)?;
    let host = parsed
        .host_str()
        .expect("parse_provider_url guarantees a host")
        .to_owned();
    if resolved.is_empty() {
        return Err(RagBuildError::InvalidConfig(
            "provider endpoint resolved to no addresses".to_owned(),
        ));
    }
    if !allow_private_url {
        for addr in &resolved {
            if is_private_ip(&addr.ip()) {
                return Err(RagBuildError::InvalidConfig(
                    "provider endpoint resolves to a private address; set allow_private_url to opt in"
                        .to_owned(),
                ));
            }
        }
    }
    finish_client(provider_client_builder(timeout).resolve_to_addrs(&host, &resolved))
}

fn provider_client_builder(timeout: Duration) -> OutboundClientBuilder {
    OutboundClientBuilder::new()
        .no_redirects()
        .request_timeout(timeout)
}

fn finish_client(builder: OutboundClientBuilder) -> Result<reqwest::Client, RagBuildError> {
    builder.build().map_err(|_| {
        // The reqwest error is dropped on purpose so no endpoint detail can
        // leak into the returned error text.
        RagBuildError::Client("provider http client construction failed".to_owned())
    })
}

/// Maps a reqwest send or read failure to a non-secret transport error.
fn map_transport(error: reqwest::Error) -> ProviderHttpError {
    if error.is_timeout() {
        ProviderHttpError::Timeout
    } else {
        ProviderHttpError::Transport("provider connection failed")
    }
}

/// Reads a provider response as JSON under the shared byte cap.
///
/// Non-2xx responses are rejected before any body parsing. The body is
/// streamed chunk by chunk and reading stops as soon as the accumulated
/// size would exceed `MAX_PROVIDER_RESPONSE_BYTES` (2 MiB). Neither the
/// body bytes nor any header or URL appear in the returned error.
#[doc(hidden)]
pub async fn bounded_json(
    mut response: reqwest::Response,
) -> Result<serde_json::Value, ProviderHttpError> {
    let status = response.status();
    if !status.is_success() {
        return Err(ProviderHttpError::HttpStatus(status.as_u16()));
    }
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_transport)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(ProviderHttpError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ProviderHttpError::MalformedJson)
}

/// Sends one provider request and reads its JSON body under one deadline.
///
/// `tokio::time::timeout` wraps the complete send and body read, so a
/// provider that accepts the connection and then stalls cannot hold the
/// request path past the configured timeout.
// Gated to its only callers, the feature-gated embedding and HTTP vector
// adapters, so a build with no provider feature carries no dead code.
// Extend the gate when a new feature-gated adapter adopts this helper.
#[cfg(any(
    feature = "embedding-openai",
    feature = "embedding-cohere",
    feature = "embedding-bedrock",
    feature = "embedding-vertex",
    feature = "vector-chroma",
    feature = "vector-pinecone",
    feature = "vector-qdrant",
    feature = "vector-weaviate"
))]
pub(crate) async fn send_bounded_json(
    request: reqwest::RequestBuilder,
    timeout: Duration,
) -> Result<serde_json::Value, ProviderHttpError> {
    match tokio::time::timeout(timeout, async {
        let response = request.send().await.map_err(map_transport)?;
        bounded_json(response).await
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(ProviderHttpError::Timeout),
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Artifact transport seam and the reqwest implementation.

use std::fmt;
#[cfg(any(test, feature = "weights"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use sbproxy_security::egress::{EgressAuthorizer, EgressDenied, EgressPurpose, HostResolver};
use zeroize::Zeroize;

use super::ArtifactError;

/// Resolved source secret whose formatted representations are always redacted.
pub struct SourceCredential {
    secret: Vec<u8>,
}

impl SourceCredential {
    /// Own resolved bearer-token bytes for one acquisition request.
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, ArtifactError> {
        let secret = secret.as_ref();
        if secret.is_empty() || secret.contains(&b'\r') || secret.contains(&b'\n') {
            return Err(ArtifactError::InvalidArtifact(
                "source credential must be nonempty and contain no line breaks".to_string(),
            ));
        }
        Ok(Self {
            secret: secret.to_vec(),
        })
    }

    #[cfg(feature = "weights")]
    pub(crate) fn bearer(&self) -> &[u8] {
        &self.secret
    }
}

impl Clone for SourceCredential {
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
        }
    }
}

impl Drop for SourceCredential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for SourceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceCredential([REDACTED])")
    }
}

impl fmt::Display for SourceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Semantics of a transport response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseDisposition {
    /// Replace any local partial with this complete response body.
    Replacement,
    /// Append this body to a matching partial.
    Append,
    /// The requested range is already complete at the source.
    RangeComplete,
}

/// One artifact-file transport request.
#[derive(Debug, Clone)]
pub struct TransportRequest {
    /// Fully resolved source URL.
    pub url: String,
    /// Existing safe partial length.
    pub offset: u64,
    /// ETag used to prevent combining source generations.
    pub if_range: Option<String>,
    /// Resolved transport-only credential.
    pub credential: Option<SourceCredential>,
}

/// Streaming artifact-file transport response.
pub struct TransportResponse {
    /// Whether the body replaces or appends to a partial.
    pub disposition: ResponseDisposition,
    /// Source entity tag used by safe resume.
    pub etag: Option<String>,
    /// Complete source length when reported.
    pub total_size: Option<u64>,
    /// Fallible byte stream.
    pub body: Pin<Box<dyn Stream<Item = Result<Bytes, ArtifactError>> + Send>>,
}

/// Dyn-safe asynchronous artifact source.
#[async_trait]
pub trait ArtifactTransport: Send + Sync {
    /// Fetch one exact file, optionally from a safe resume offset.
    async fn get(&self, request: TransportRequest) -> Result<TransportResponse, ArtifactError>;
}

/// Transport used by builds that intentionally omit network weight
/// support. Local `file:` artifacts and verified cache hits still work;
/// an HTTP miss fails with an actionable feature message.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableArtifactTransport;

#[async_trait]
impl ArtifactTransport for UnavailableArtifactTransport {
    async fn get(&self, _request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        Err(ArtifactError::Transport(
            "network artifact acquisition requires the model-weights feature".to_string(),
        ))
    }
}

/// Authorize an artifact / engine download URL when an authorizer is
/// present. `None` preserves legacy ungated downloads (omitted config).
pub fn authorize_artifact_url(
    authorizer: Option<&EgressAuthorizer>,
    purpose: EgressPurpose,
    url: &str,
    resolver: &dyn HostResolver,
) -> Result<(), EgressDenied> {
    let Some(auth) = authorizer else {
        return Ok(());
    };
    auth.authorize(purpose, url, resolver).map(|_| ())
}

/// Engine-download seam: today always omitted-config (legacy). GS may
/// thread an authorizer later; the call site still goes through the
/// shared closed vocabulary.
#[cfg(feature = "weights")]
pub(crate) fn authorize_engine_download(url: &str) -> Result<(), String> {
    authorize_artifact_url(
        None,
        EgressPurpose::EngineArtifact,
        url,
        &PublicPinResolver,
    )
    .map_err(|e| format!("egress denied: {e:?}"))
}

/// Resolver that pins a fixed public address so gates never touch the
/// network during unit tests. Production GS wiring may inject real DNS.
#[cfg(any(test, feature = "weights"))]
pub(crate) struct PublicPinResolver;

#[cfg(any(test, feature = "weights"))]
impl HostResolver for PublicPinResolver {
    fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port,
        )])
    }
}

/// Redirect-following HTTP artifact transport.
#[cfg(feature = "weights")]
#[derive(Debug, Clone)]
pub struct HttpArtifactTransport {
    client: reqwest::Client,
    egress: Option<EgressAuthorizer>,
}

#[cfg(feature = "weights")]
impl HttpArtifactTransport {
    /// Construct a transport using reqwest's safe default redirect policy.
    pub fn new() -> Result<Self, ArtifactError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|error| ArtifactError::Transport(format!("build HTTP client: {error}")))?;
        Ok(Self {
            client,
            egress: None,
        })
    }

    /// Attach a fail-closed egress authorizer (`EgressPurpose::ModelArtifact`).
    pub fn with_egress(mut self, authorizer: EgressAuthorizer) -> Self {
        self.egress = Some(authorizer);
        self
    }
}

#[cfg(feature = "weights")]
#[async_trait]
impl ArtifactTransport for HttpArtifactTransport {
    async fn get(&self, request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        use futures::StreamExt;
        use reqwest::header::{AUTHORIZATION, CONTENT_RANGE, ETAG, IF_RANGE, RANGE};

        authorize_artifact_url(
            self.egress.as_ref(),
            EgressPurpose::ModelArtifact,
            &request.url,
            &PublicPinResolver,
        )
        .map_err(|denied| ArtifactError::Transport(format!("egress denied: {denied:?}")))?;

        let mut builder = self.client.get(&request.url);
        if request.offset > 0 {
            builder = builder.header(RANGE, format!("bytes={}-", request.offset));
            if let Some(if_range) = &request.if_range {
                builder = builder.header(IF_RANGE, if_range);
            }
        }
        if let Some(credential) = &request.credential {
            let mut bearer = b"Bearer ".to_vec();
            bearer.extend_from_slice(credential.bearer());
            let header = reqwest::header::HeaderValue::from_bytes(&bearer).map_err(|_| {
                ArtifactError::InvalidArtifact(
                    "source credential is not a valid header".to_string(),
                )
            });
            bearer.fill(0);
            let mut header = header?;
            header.set_sensitive(true);
            builder = builder.header(AUTHORIZATION, header);
        }

        let response = builder.send().await.map_err(|error| {
            ArtifactError::Transport(format!("request {}: {error}", request.url))
        })?;
        let status = response.status();
        let disposition = match status.as_u16() {
            200 => ResponseDisposition::Replacement,
            206 if request.offset > 0 => ResponseDisposition::Append,
            416 if request.offset > 0 => ResponseDisposition::RangeComplete,
            _ => {
                return Err(ArtifactError::HttpStatus {
                    url: request.url,
                    status: status.as_u16(),
                })
            }
        };
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let total_size = match disposition {
            ResponseDisposition::Replacement => response.content_length(),
            ResponseDisposition::Append | ResponseDisposition::RangeComplete => response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_content_range_total),
        };
        let url = request.url;
        let body = response.bytes_stream().map(move |result| {
            result.map_err(|error| {
                ArtifactError::Transport(format!("read response body for {url}: {error}"))
            })
        });
        Ok(TransportResponse {
            disposition,
            etag,
            total_size,
            body: Box::pin(body),
        })
    }
}

#[cfg(feature = "weights")]
fn parse_content_range_total(value: &str) -> Option<u64> {
    value.rsplit_once('/')?.1.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use sbproxy_security::egress::{EgressConfig, PurposeAllowlist};

    #[cfg(feature = "weights")]
    #[test]
    fn source_credentials_are_usable_only_through_the_private_transport_accessor() {
        let secret = b"hf_fixture_secret";
        let credential = SourceCredential::new(secret).expect("credential");

        assert_eq!(credential.bearer(), secret);
        assert_eq!(format!("{credential:?}"), "SourceCredential([REDACTED])");
        assert_eq!(credential.to_string(), "[REDACTED]");
        assert!(!format!("{credential:?}").contains("hf_fixture_secret"));
    }

    fn enforce_model_artifact(hosts: &[&str]) -> EgressAuthorizer {
        let mut allow = PurposeAllowlist::default();
        for h in hosts {
            allow.hosts.insert((*h).to_string());
        }
        allow.schemes.insert("https".to_string());
        allow.ports.insert(443);
        let mut purposes = HashMap::new();
        purposes.insert(EgressPurpose::ModelArtifact, allow);
        EgressAuthorizer::new(EgressConfig { purposes })
    }

    #[test]
    fn model_artifact_egress_denies_unlisted_host_with_shared_vocabulary() {
        let auth = enforce_model_artifact(&["huggingface.co"]);
        let err = authorize_artifact_url(
            Some(&auth),
            EgressPurpose::ModelArtifact,
            "https://evil.example/model.bin",
            &PublicPinResolver,
        )
        .expect_err("unlisted artifact host");
        assert_eq!(err, EgressDenied::UnlistedHost);
    }

    #[test]
    fn omitted_egress_preserves_legacy_artifact_compatibility() {
        authorize_artifact_url(
            None,
            EgressPurpose::ModelArtifact,
            "https://evil.example/model.bin",
            &PublicPinResolver,
        )
        .expect("omitted egress must not deny");
    }

    #[test]
    fn engine_artifact_shares_closed_denial_vocabulary() {
        let mut allow = PurposeAllowlist::default();
        allow.hosts.insert("github.com".to_string());
        allow.schemes.insert("https".to_string());
        allow.ports.insert(443);
        let mut purposes = HashMap::new();
        purposes.insert(EgressPurpose::EngineArtifact, allow);
        let auth = EgressAuthorizer::new(EgressConfig { purposes });
        let err = authorize_artifact_url(
            Some(&auth),
            EgressPurpose::EngineArtifact,
            "https://evil.example/llama.tar.gz",
            &PublicPinResolver,
        )
        .expect_err("unlisted engine host");
        assert_eq!(err, EgressDenied::UnlistedHost);
    }
}

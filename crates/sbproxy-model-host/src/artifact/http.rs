// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Artifact transport seam and the reqwest implementation.

use std::fmt;
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
#[cfg(feature = "weights")]
use sbproxy_security::egress::{
    evaluate_hop, record_egress_refused, record_egress_seen, CachedSystemResolver,
    EgressSightingStatus, RedirectRule,
};
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
///
/// WOR-2165: the resolver is live. With no authorizer attached this
/// short-circuits before resolving, so the change costs nothing until
/// an operator configures egress.
#[cfg(feature = "weights")]
pub(crate) fn authorize_engine_download(url: &str) -> Result<(), String> {
    // WOR-2476: the authorizer here is always `None` (no per-engine config
    // exists yet to attach one), so every engine-artifact download is
    // honestly `Ungated` until a real authorizer is threaded through.
    // Stamping still proves the endpoint is reached, and this one choke
    // point covers all three engine-release callers.
    record_egress_seen(
        EgressPurpose::EngineArtifact,
        url,
        "engine_artifact",
        EgressSightingStatus::Ungated,
        None,
    );
    authorize_artifact_url(
        None,
        EgressPurpose::EngineArtifact,
        url,
        &CachedSystemResolver,
    )
    .map_err(|e| format!("egress denied: {e:?}"))
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
    /// Construct a transport that follows redirects only under the
    /// governed egress contract (WOR-2165).
    ///
    /// The client's own redirect following is off. Artifact downloads
    /// legitimately hop off the origin host (a registry hands the
    /// request to object storage or a CDN), so a cross-origin hop is
    /// followed rather than refused, but
    /// each one is re-authorized first and the source credential is
    /// dropped before the request leaves the origin it was minted for.
    pub fn new() -> Result<Self, ArtifactError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
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

    /// Follow the redirect chain for one artifact `GET`, re-authorizing
    /// each hop (WOR-2165).
    ///
    /// A registry handing a download to object storage is the normal
    /// case, so a cross-origin hop is followed rather than refused. The
    /// source credential does not follow it: the bearer was minted for
    /// the origin the operator named, and a presigned storage URL
    /// carries its own authorization in the query string.
    async fn follow_governed(
        &self,
        mut request: reqwest::Request,
        origin_label: &str,
    ) -> Result<reqwest::Response, String> {
        let mut hop = 0usize;
        loop {
            let replay = request.try_clone();
            let from = request.url().clone();
            let response = self
                .client
                .execute(request)
                .await
                .map_err(|error| error.to_string())?;
            if !response.status().is_redirection() {
                return Ok(response);
            }
            let Some(location) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
            else {
                return Ok(response);
            };
            hop += 1;
            let next = evaluate_hop(
                self.egress.as_ref(),
                EgressPurpose::ModelArtifact,
                &from,
                &location,
                hop,
                RedirectRule::CrossOriginAllowed,
                &CachedSystemResolver,
            )
            .map_err(|denied| {
                record_egress_refused(EgressPurpose::ModelArtifact, denied, "unset", origin_label);
                format!("egress denied: {denied:?}")
            })?;
            let Some(mut replay) = replay else {
                return Ok(response);
            };
            if next.strip_credentials {
                replay.headers_mut().remove(reqwest::header::AUTHORIZATION);
            }
            *replay.url_mut() = next.url;
            request = replay;
        }
    }
}

#[cfg(feature = "weights")]
#[async_trait]
impl ArtifactTransport for HttpArtifactTransport {
    async fn get(&self, request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        use futures::StreamExt;
        use reqwest::header::{AUTHORIZATION, CONTENT_RANGE, ETAG, IF_RANGE, RANGE};

        let artifact_host = reqwest::Url::parse(&request.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_else(|| "unset".to_string());
        // WOR-2476: every artifact URL lands in the egress inventory,
        // whether an authorizer is configured or not. `authorize_artifact_url`
        // collapses "no authorizer" to `Ok(())`, so the stamp inspects
        // `self.egress` directly rather than trusting that result.
        if self.egress.is_none() {
            record_egress_seen(
                EgressPurpose::ModelArtifact,
                &request.url,
                &artifact_host,
                EgressSightingStatus::Ungated,
                None,
            );
        } else {
            match authorize_artifact_url(
                self.egress.as_ref(),
                EgressPurpose::ModelArtifact,
                &request.url,
                &CachedSystemResolver,
            ) {
                Ok(()) => {
                    record_egress_seen(
                        EgressPurpose::ModelArtifact,
                        &request.url,
                        &artifact_host,
                        EgressSightingStatus::Allowed,
                        None,
                    );
                }
                Err(denied) => {
                    record_egress_seen(
                        EgressPurpose::ModelArtifact,
                        &request.url,
                        &artifact_host,
                        EgressSightingStatus::Denied,
                        Some(denied),
                    );
                    record_egress_refused(
                        EgressPurpose::ModelArtifact,
                        denied,
                        "unset",
                        &artifact_host,
                    );
                    return Err(ArtifactError::Transport(format!(
                        "egress denied: {denied:?}"
                    )));
                }
            }
        }

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

        let built = builder.build().map_err(|error| {
            ArtifactError::Transport(format!("request {}: {error}", request.url))
        })?;
        let response = self
            .follow_governed(built, &artifact_host)
            .await
            .map_err(|error| {
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

/// Xet-aware artifact transport over `hf-hub`'s managed client.
///
/// `hf-hub` downloads through its own content-addressed cache
/// (`HF_HUB_CACHE`), speaking the Xet chunk-deduplication protocol
/// transparently: a chunk already local or shared with another cached
/// file is never re-fetched. It also owns resumability of one file's
/// own download internally, so this transport always reports the
/// completed local file as one [`ResponseDisposition::Replacement`]
/// rather than reimplementing byte-range resume against it; the
/// artifact cache above this seam (`artifact/cache.rs`) already owns
/// the content-addressed artifact cache, hardlinking, and resume
/// bookkeeping, and a `Replacement` is always a correct response no
/// matter what offset the caller asked to resume from.
#[cfg(feature = "hf-xet-transport")]
#[derive(Debug, Clone, Default)]
pub struct HfHubArtifactTransport;

#[cfg(feature = "hf-xet-transport")]
impl HfHubArtifactTransport {
    /// Construct the transport. `hf-hub` reads `HF_TOKEN`, `HF_ENDPOINT`,
    /// and `HF_HUB_CACHE` from the environment on its own when a request
    /// carries no explicit credential.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "hf-xet-transport")]
#[async_trait]
impl ArtifactTransport for HfHubArtifactTransport {
    async fn get(&self, request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        use futures::StreamExt;

        let (owner, repo, revision, filename) =
            parse_hf_resolve_url(&request.url).ok_or_else(|| {
                ArtifactError::Transport(format!("not a Hugging Face resolve URL: {}", request.url))
            })?;

        let client = match &request.credential {
            Some(credential) => {
                let token = std::str::from_utf8(credential.bearer()).map_err(|_| {
                    ArtifactError::InvalidArtifact(
                        "source credential is not valid UTF-8".to_string(),
                    )
                })?;
                hf_hub::HFClient::builder()
                    .token(token)
                    .build()
                    .map_err(|error| {
                        ArtifactError::Transport(format!("build hf-hub client: {error}"))
                    })?
            }
            None => hf_hub::HFClient::new().map_err(|error| {
                ArtifactError::Transport(format!("build hf-hub client: {error}"))
            })?,
        };

        let path = client
            .model(&owner, &repo)
            .download_file()
            .filename(&filename)
            .revision(&revision)
            .send()
            .await
            .map_err(|error| {
                ArtifactError::Transport(format!(
                    "hf-hub download {owner}/{repo}@{revision}/{filename}: {error}"
                ))
            })?;

        let total_size = tokio::fs::metadata(&path)
            .await
            .map_err(|source| super::io_error("read hf-hub cached artifact", &path, source))?
            .len();
        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|source| super::io_error("open hf-hub cached artifact", &path, source))?;
        let body = tokio_util::io::ReaderStream::new(file).map(|chunk| {
            chunk.map_err(|error| {
                ArtifactError::Transport(format!("read hf-hub cached artifact: {error}"))
            })
        });

        Ok(TransportResponse {
            disposition: ResponseDisposition::Replacement,
            etag: None,
            total_size: Some(total_size),
            body: Box::pin(body),
        })
    }
}

/// Recover `(owner, repo, revision, filename)` from a resolve URL in the
/// exact shape `artifact/mod.rs`'s `hf_url()` builds:
/// `{endpoint}/{owner}/{repo}/resolve/{revision}/{filename}`. `filename`
/// may itself contain `/` (a nested path inside the repo).
#[cfg(feature = "hf-xet-transport")]
fn parse_hf_resolve_url(url: &str) -> Option<(String, String, String, String)> {
    let endpoint =
        std::env::var("HF_ENDPOINT").unwrap_or_else(|_| "https://huggingface.co".to_string());
    let prefix = format!("{}/", endpoint.trim_end_matches('/'));
    let rest = url.strip_prefix(&prefix)?;
    let mut segments = rest.splitn(5, '/');
    let owner = segments.next()?.to_string();
    let repo = segments.next()?.to_string();
    if segments.next()? != "resolve" {
        return None;
    }
    let revision = segments.next()?.to_string();
    let filename = segments.next()?.to_string();
    if owner.is_empty() || repo.is_empty() || revision.is_empty() || filename.is_empty() {
        return None;
    }
    Some((owner, repo, revision, filename))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_security::egress::{EgressConfig, PurposeAllowlist};
    use std::collections::HashMap;

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

    /// Test resolver mapping a host to fixed addresses. Production
    /// gates pass `CachedSystemResolver`.
    struct MapResolver {
        map: HashMap<String, Vec<std::net::SocketAddr>>,
    }

    impl MapResolver {
        fn new(entries: Vec<(&str, Vec<std::net::SocketAddr>)>) -> Self {
            Self {
                map: entries
                    .into_iter()
                    .map(|(h, a)| (h.to_string(), a))
                    .collect(),
            }
        }
    }

    impl HostResolver for MapResolver {
        fn resolve(&self, host: &str, _port: u16) -> Result<Vec<std::net::SocketAddr>, ()> {
            self.map.get(host).cloned().ok_or(())
        }
    }

    fn public_addr(port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            port,
        )
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
            &MapResolver::new(vec![("evil.example", vec![public_addr(443)])]),
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
            &MapResolver::new(vec![]),
        )
        .expect("omitted egress must not deny, and must not even resolve");
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
            &MapResolver::new(vec![("evil.example", vec![public_addr(443)])]),
        )
        .expect_err("unlisted engine host");
        assert_eq!(err, EgressDenied::UnlistedHost);
    }

    #[cfg(feature = "hf-xet-transport")]
    #[test]
    fn parse_hf_resolve_url_recovers_owner_repo_revision_and_nested_filename() {
        let parsed =
            parse_hf_resolve_url("https://huggingface.co/Org/Repo/resolve/main/onnx/model.onnx");
        assert_eq!(
            parsed,
            Some((
                "Org".to_string(),
                "Repo".to_string(),
                "main".to_string(),
                "onnx/model.onnx".to_string(),
            ))
        );
    }

    #[cfg(feature = "hf-xet-transport")]
    #[test]
    fn parse_hf_resolve_url_rejects_a_non_resolve_url() {
        assert_eq!(
            parse_hf_resolve_url("https://huggingface.co/Org/Repo/blob/main/file.bin"),
            None
        );
    }

    #[cfg(feature = "hf-xet-transport")]
    #[tokio::test]
    #[ignore = "requires live network access to huggingface.co"]
    async fn hf_hub_transport_resolves_a_small_public_weight_file_through_xet() {
        use futures::StreamExt;

        let transport = HfHubArtifactTransport::new();
        let url = "https://huggingface.co/hf-internal-testing/tiny-random-LlamaForCausalLM/resolve/main/model.safetensors";
        let response = transport
            .get(TransportRequest {
                url: url.to_string(),
                offset: 0,
                if_range: None,
                credential: None,
            })
            .await
            .expect("hf-hub download");
        assert_eq!(response.disposition, ResponseDisposition::Replacement);
        let total_size = response.total_size.expect("reports a size");
        assert!(
            total_size > 8,
            "a safetensors file has at least a header length prefix"
        );

        let mut body = response.body;
        let mut bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            bytes.extend_from_slice(&chunk.expect("read chunk"));
        }
        assert_eq!(
            bytes.len() as u64,
            total_size,
            "reported size matches the streamed body"
        );

        // safetensors: an 8-byte little-endian header length, then that
        // many bytes of a JSON header -- the existing sha256 verification
        // layer above this transport checks file identity; this checks
        // the bytes it received are a well-formed safetensors file.
        let header_len = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        assert!(bytes.len() >= 8 + header_len);
        let header = std::str::from_utf8(&bytes[8..8 + header_len]).expect("header is UTF-8");
        assert!(
            header.trim_start().starts_with('{'),
            "safetensors header is a JSON object"
        );
    }
}

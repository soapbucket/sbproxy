//! gRPC action handler.
//!
//! Proxies incoming requests to an upstream gRPC server. Supports
//! grpc://, grpcs://, http://, and https:// URL schemes with
//! optional authority override and configurable timeout.
//!
//! Beyond transparent passthrough the action can also transcode between
//! REST/JSON and gRPC (driven by a protobuf descriptor set and
//! `google.api.http`-style route templates) and bridge browser gRPC-Web
//! clients to the native gRPC upstream. The descriptor and route mapping
//! are compiled once at config load via [`sbproxy_transport::Transcoder`];
//! the heavy lifting (JSON <-> protobuf, frame and trailer handling,
//! gRPC <-> HTTP status mapping) lives in `sbproxy-transport`. Neither
//! mode is available over the proxy's HTTP/3 listener: the `grpc` action
//! returns `501` there, the same as plain gRPC passthrough.

use std::sync::Arc;

use sbproxy_transport::{HttpMethod, RouteSpec, Transcoder};
use serde::Deserialize;

use super::ForwardingHeaderControls;

fn default_timeout_secs() -> u64 {
    30
}

/// One REST <-> gRPC transcoding route in the action config.
///
/// Binds an HTTP method and a `google.api.http` path template to a
/// fully-qualified gRPC method. The `body` field controls how the HTTP
/// request body maps into the gRPC request message.
#[derive(Debug, Clone, Deserialize)]
pub struct GrpcTranscodeRoute {
    /// HTTP method to match (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`).
    pub method: String,
    /// `google.api.http` path template, for example
    /// `/v1/messages/{message_id}`.
    pub path: String,
    /// Fully-qualified gRPC method, for example
    /// `myapi.v1.Messages.GetMessage`.
    pub grpc_method: String,
    /// How the HTTP body maps into the request message. Omit (or use
    /// `"*"`) to decode the whole body as the request message; name a
    /// field to decode the body into that single field.
    #[serde(default)]
    pub body: Option<String>,
}

/// REST <-> gRPC transcoding configuration for the `grpc` action.
///
/// When present, the proxy can accept HTTP/JSON requests on the
/// configured routes and translate them into unary gRPC calls against
/// the upstream, translating the gRPC response back to JSON. When
/// absent, the action is plain gRPC passthrough.
#[derive(Debug, Clone, Deserialize)]
pub struct GrpcTranscodeConfig {
    /// Path to a compiled protobuf `FileDescriptorSet` (the output of
    /// `protoc --descriptor_set_out=...` or `prost`/`tonic`'s
    /// `file_descriptor_set`). Read once at config load.
    pub descriptor_set: String,
    /// The REST routes to expose, each bound to a gRPC method.
    pub routes: Vec<GrpcTranscodeRoute>,
}

/// gRPC action config - proxies requests to an upstream gRPC server.
#[derive(Deserialize)]
pub struct GrpcAction {
    /// Backend gRPC URL (grpc://, grpcs://, http://, or https://).
    pub url: String,
    /// Whether the upstream connection requires TLS.
    #[serde(default)]
    pub tls: bool,
    /// Optional :authority override for the HTTP/2 connection.
    #[serde(default)]
    pub authority: Option<String>,
    /// Request timeout in seconds (default: 30).
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Allow browser gRPC-Web clients (HTTP/1.1 with base64 or binary
    /// framing) to reach the native gRPC upstream. Defaults to `false`
    /// so the action stays plain passthrough unless opted in.
    #[serde(default)]
    pub grpc_web: bool,
    /// Optional REST <-> gRPC transcoding configuration.
    #[serde(default)]
    pub transcode: Option<GrpcTranscodeConfig>,
    /// Per-action opt-out flags for the standard proxy forwarding headers.
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
    /// Compiled transcoder, built once at config load from `transcode`.
    /// `None` when transcoding is not configured. Shared behind an `Arc`
    /// so the compiled handler chain can clone a cheap handle.
    #[serde(skip)]
    pub transcoder: Option<Arc<Transcoder>>,
}

impl std::fmt::Debug for GrpcAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcAction")
            .field("url", &self.url)
            .field("tls", &self.tls)
            .field("authority", &self.authority)
            .field("timeout_secs", &self.timeout_secs)
            .field("grpc_web", &self.grpc_web)
            .field("transcode", &self.transcode)
            .field("forwarding", &self.forwarding)
            .field(
                "transcoder",
                &self.transcoder.as_ref().map(|_| "<compiled>"),
            )
            .finish()
    }
}

impl GrpcAction {
    /// Build a GrpcAction from a generic JSON config value.
    ///
    /// When a `transcode` block is present, its descriptor set is read
    /// from disk and compiled into a [`Transcoder`]; a missing file,
    /// malformed descriptor, unknown gRPC method, or bad path template
    /// fails config load rather than the first request.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut action: Self = serde_json::from_value(value)?;
        action.transcoder = action.build_transcoder()?;
        Ok(action)
    }

    /// Compile the transcoder from the `transcode` block, if any.
    fn build_transcoder(&self) -> anyhow::Result<Option<Arc<Transcoder>>> {
        let cfg = match &self.transcode {
            Some(c) => c,
            None => return Ok(None),
        };
        let descriptor_bytes = std::fs::read(&cfg.descriptor_set).map_err(|e| {
            anyhow::anyhow!(
                "grpc transcode: failed to read descriptor set '{}': {e}",
                cfg.descriptor_set
            )
        })?;
        let mut routes = Vec::with_capacity(cfg.routes.len());
        for route in &cfg.routes {
            let method = HttpMethod::parse(&route.method).ok_or_else(|| {
                anyhow::anyhow!("grpc transcode: unsupported HTTP method '{}'", route.method)
            })?;
            routes.push(RouteSpec {
                method,
                path_template: route.path.clone(),
                grpc_method: route.grpc_method.clone(),
                body: route.body.clone(),
            });
        }
        let transcoder = Transcoder::from_descriptor_set(&descriptor_bytes, &routes)?;
        Ok(Some(Arc::new(transcoder)))
    }

    /// Parse the gRPC URL into (host, port, tls) for upstream peer.
    ///
    /// Converts grpc:// to http:// and grpcs:// to https:// before parsing.
    /// The `tls` field in the config can override scheme-based TLS detection.
    pub fn parse_upstream(&self) -> anyhow::Result<(String, u16, bool)> {
        // The result also depends on `self.tls`, so include it in the memo
        // key (two gRPC actions with the same URL but different `tls:` must
        // not share a cache entry). WOR-1698.
        let key = format!("{}\u{0}{}", self.url, self.tls);
        super::memoized_upstream(&key, || {
            let normalized = if self.url.starts_with("grpcs://") {
                self.url.replacen("grpcs://", "https://", 1)
            } else if self.url.starts_with("grpc://") {
                self.url.replacen("grpc://", "http://", 1)
            } else {
                self.url.clone()
            };

            let parsed = url::Url::parse(&normalized)?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host in gRPC URL"))?
                .to_string();
            let tls = self.tls || parsed.scheme() == "https";
            let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
            Ok((host, port, tls))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_from_config_full() {
        let json = serde_json::json!({
            "type": "grpc",
            "url": "grpcs://grpc.example.com:50051",
            "tls": true,
            "authority": "grpc.example.com",
            "timeout_secs": 60
        });
        let grpc = GrpcAction::from_config(json).unwrap();
        assert_eq!(grpc.url, "grpcs://grpc.example.com:50051");
        assert!(grpc.tls);
        assert_eq!(grpc.authority.as_deref(), Some("grpc.example.com"));
        assert_eq!(grpc.timeout_secs, 60);
    }

    #[test]
    fn grpc_from_config_defaults() {
        let json = serde_json::json!({
            "type": "grpc",
            "url": "grpc://localhost:50051"
        });
        let grpc = GrpcAction::from_config(json).unwrap();
        assert!(!grpc.tls);
        assert!(grpc.authority.is_none());
        assert_eq!(grpc.timeout_secs, 30);
        // Transcoding and gRPC-Web stay off unless opted in, so existing
        // gRPC passthrough configs keep working unchanged.
        assert!(!grpc.grpc_web);
        assert!(grpc.transcode.is_none());
        assert!(grpc.transcoder.is_none());
    }

    #[test]
    fn grpc_web_opt_in_parses() {
        let json = serde_json::json!({
            "type": "grpc",
            "url": "grpc://localhost:50051",
            "grpc_web": true
        });
        let grpc = GrpcAction::from_config(json).unwrap();
        assert!(grpc.grpc_web);
    }

    #[test]
    fn transcode_with_missing_descriptor_file_fails_config_load() {
        let json = serde_json::json!({
            "type": "grpc",
            "url": "grpc://localhost:50051",
            "transcode": {
                "descriptor_set": "/no/such/descriptor.pb",
                "routes": [
                    {"method": "POST", "path": "/v1/echo", "grpc_method": "x.Y.Z"}
                ]
            }
        });
        // A missing descriptor must fail loudly at config load, not at
        // the first request.
        assert!(GrpcAction::from_config(json).is_err());
    }

    #[test]
    fn transcode_with_bad_method_fails_config_load() {
        // The descriptor file is read before routes are validated, so an
        // empty-but-present file is enough to reach (and fail at) the
        // unsupported HTTP verb check.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sbproxy-grpc-desc-{}.pb", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        let json = serde_json::json!({
            "type": "grpc",
            "url": "grpc://localhost:50051",
            "transcode": {
                "descriptor_set": path.to_string_lossy(),
                "routes": [
                    {"method": "TRACE", "path": "/v1/echo", "grpc_method": "x.Y.Z"}
                ]
            }
        });
        let result = GrpcAction::from_config(json);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn grpc_from_config_missing_url() {
        let json = serde_json::json!({"type": "grpc"});
        assert!(GrpcAction::from_config(json).is_err());
    }

    #[test]
    fn parse_upstream_grpc() {
        let grpc = GrpcAction {
            url: "grpc://backend:50051".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            grpc_web: false,
            transcode: None,
            forwarding: Default::default(),
            transcoder: None,
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 50051);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_grpcs() {
        let grpc = GrpcAction {
            url: "grpcs://api.example.com".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            grpc_web: false,
            transcode: None,
            forwarding: Default::default(),
            transcoder: None,
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_tls_override() {
        let grpc = GrpcAction {
            url: "grpc://secure-backend:50051".to_string(),
            tls: true,
            authority: None,
            timeout_secs: 30,
            grpc_web: false,
            transcode: None,
            forwarding: Default::default(),
            transcoder: None,
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "secure-backend");
        assert_eq!(port, 50051);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_http_url() {
        let grpc = GrpcAction {
            url: "http://localhost:9090".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            grpc_web: false,
            transcode: None,
            forwarding: Default::default(),
            transcoder: None,
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 9090);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_https_url() {
        let grpc = GrpcAction {
            url: "https://grpc.example.com".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            grpc_web: false,
            transcode: None,
            forwarding: Default::default(),
            transcoder: None,
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "grpc.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_invalid_url() {
        let grpc = GrpcAction {
            url: "not valid".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            grpc_web: false,
            transcode: None,
            forwarding: Default::default(),
            transcoder: None,
        };
        assert!(grpc.parse_upstream().is_err());
    }
}

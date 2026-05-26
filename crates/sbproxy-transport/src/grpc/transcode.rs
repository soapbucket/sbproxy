//! Descriptor-driven REST <-> gRPC transcoding.
//!
//! A [`Transcoder`] is built once at config-load time from a compiled
//! protobuf `FileDescriptorSet` (the output of
//! `protoc --descriptor_set_out=...` or `prost`/`tonic`'s
//! `file_descriptor_set`). It indexes the services and methods in the
//! set and binds each transcoding route (an HTTP method plus a
//! `google.api.http` path template) to a fully-qualified gRPC method.
//!
//! At request time [`Transcoder::transcode_request`] turns an inbound
//! HTTP/JSON request into the unary gRPC frame to send upstream, and
//! [`Transcoder::transcode_response`] turns the gRPC response frame back
//! into JSON. Errors carried in the `grpc-status` trailer are mapped to
//! HTTP status codes via [`crate::grpc::GrpcStatus`].
//!
//! Route bindings are supplied explicitly as [`RouteSpec`] entries in
//! config. This is deliberate: it does not require the descriptor set to
//! also embed the `google.api.http` annotation protos, so an operator can
//! point at any plain `FileDescriptorSet` and map HTTP routes to gRPC
//! methods directly.

use std::collections::BTreeMap;

use prost::Message as _;
use prost_reflect::{
    DescriptorPool, DynamicMessage, MethodDescriptor, ReflectMessage as _, SerializeOptions,
};

use super::frame;
use super::status::GrpcStatus;
use super::template::PathTemplate;

/// The HTTP method a transcoding route binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

impl HttpMethod {
    /// Parse a method name (case-insensitive). Returns `None` for verbs
    /// that have no `google.api.http` rule field.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// A single transcoding route: bind an HTTP method and path template to
/// a fully-qualified gRPC method, optionally mapping the HTTP body to a
/// single request field.
#[derive(Debug, Clone)]
pub struct RouteSpec {
    /// HTTP method the route matches.
    pub method: HttpMethod,
    /// `google.api.http` path template, for example
    /// `/v1/messages/{message_id}`.
    pub path_template: String,
    /// Fully-qualified gRPC method name, for example
    /// `sbproxy_e2e.echo.Echo.Hello`.
    pub grpc_method: String,
    /// How the HTTP body maps into the request message. `None` or
    /// `Some("*")` means the whole body is the request message; a field
    /// name means the body is decoded into that single field.
    pub body: Option<String>,
}

/// A compiled route ready for matching at request time.
#[derive(Debug, Clone)]
struct CompiledRoute {
    method: HttpMethod,
    template: PathTemplate,
    grpc_method: String,
    body: Option<String>,
}

/// The gRPC path (`:path` header value) plus the protobuf request bytes
/// and the framed gRPC body for a transcoded unary call.
#[derive(Debug, Clone)]
pub struct TranscodedRequest {
    /// The gRPC `:path` to send upstream, for example
    /// `/sbproxy_e2e.echo.Echo/Hello`.
    pub grpc_path: String,
    /// The length-prefixed gRPC frame (5-byte header + protobuf body).
    pub framed_body: Vec<u8>,
}

/// The outcome of mapping a gRPC response back to HTTP/JSON.
#[derive(Debug, Clone)]
pub struct TranscodedResponse {
    /// HTTP status code derived from the gRPC status.
    pub http_status: u16,
    /// JSON response body. On success this is the serialized response
    /// message; on a gRPC error it is a `{ "code", "status", "message" }`
    /// envelope.
    pub json_body: Vec<u8>,
}

/// A descriptor-driven REST <-> gRPC transcoder.
pub struct Transcoder {
    pool: DescriptorPool,
    routes: Vec<CompiledRoute>,
}

impl Transcoder {
    /// Build a transcoder from an encoded `FileDescriptorSet` and a set
    /// of explicit routes.
    ///
    /// `descriptor_set` is the raw bytes of a serialized
    /// `google.protobuf.FileDescriptorSet`. Each [`RouteSpec`] is
    /// compiled and validated against the descriptor pool; an unknown
    /// gRPC method or a malformed path template is an error so config
    /// load fails loudly rather than at the first request.
    pub fn from_descriptor_set(
        descriptor_set: &[u8],
        routes: &[RouteSpec],
    ) -> anyhow::Result<Self> {
        let pool = DescriptorPool::decode(descriptor_set)
            .map_err(|e| anyhow::anyhow!("failed to decode FileDescriptorSet: {e}"))?;
        let mut compiled = Vec::with_capacity(routes.len());
        for spec in routes {
            // Validate the gRPC method exists in the pool.
            Self::lookup_method(&pool, &spec.grpc_method)?;
            let template = PathTemplate::parse(&spec.path_template)?;
            compiled.push(CompiledRoute {
                method: spec.method,
                template,
                grpc_method: spec.grpc_method.clone(),
                body: spec.body.clone(),
            });
        }
        Ok(Self {
            pool,
            routes: compiled,
        })
    }

    /// Number of compiled routes.
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Look up a gRPC method by its fully-qualified name in the pool.
    ///
    /// Accepts both dot-separated (`pkg.Service.Method`) and the gRPC
    /// path form (`pkg.Service/Method`).
    fn lookup_method(pool: &DescriptorPool, grpc_method: &str) -> anyhow::Result<MethodDescriptor> {
        let (service_name, method_name) = if let Some((svc, m)) = grpc_method.rsplit_once('/') {
            (svc, m)
        } else if let Some((svc, m)) = grpc_method.rsplit_once('.') {
            (svc, m)
        } else {
            anyhow::bail!("gRPC method name must be fully qualified: {grpc_method}");
        };
        let service = pool
            .get_service_by_name(service_name)
            .ok_or_else(|| anyhow::anyhow!("service not found in descriptor: {service_name}"))?;
        let found = service.methods().find(|m| m.name() == method_name);
        found.ok_or_else(|| {
            anyhow::anyhow!("method {method_name} not found on service {service_name}")
        })
    }

    /// The gRPC `:path` for a method (`/pkg.Service/Method`).
    fn grpc_path(method: &MethodDescriptor) -> String {
        format!("/{}/{}", method.parent_service().full_name(), method.name())
    }

    /// Transcode an inbound HTTP/JSON request into a unary gRPC frame.
    ///
    /// `http_method` is the request verb, `path` the request target
    /// (with or without a query string), and `body` the raw request
    /// body (empty for verbs that carry none). The path template
    /// bindings, the JSON body, and the query parameters are merged into
    /// the gRPC request message in that precedence order (later wins for
    /// the body, path bindings always win since they are part of the
    /// resource name).
    ///
    /// Returns `Ok(None)` when no configured route matches, so the
    /// caller can fall through to plain proxying or return a 404.
    pub fn transcode_request(
        &self,
        http_method: &str,
        path: &str,
        body: &[u8],
    ) -> anyhow::Result<Option<TranscodedRequest>> {
        let method = match HttpMethod::parse(http_method) {
            Some(m) => m,
            None => return Ok(None),
        };
        let route = match self
            .routes
            .iter()
            .find(|r| r.method == method && r.template.match_path(path).is_some())
        {
            Some(r) => r,
            None => return Ok(None),
        };
        let bindings = route
            .template
            .match_path(path)
            .expect("route matched above");

        let descriptor = Self::lookup_method(&self.pool, &route.grpc_method)?;
        let input = descriptor.input();

        // Start from the JSON body (or an empty message) and overlay the
        // path bindings and query parameters.
        let mut message = if body.is_empty() {
            DynamicMessage::new(input.clone())
        } else {
            let body_field = route.body.as_deref().unwrap_or("*");
            if body_field == "*" {
                let mut de = serde_json::Deserializer::from_slice(body);
                DynamicMessage::deserialize(input.clone(), &mut de).map_err(|e| {
                    anyhow::anyhow!("request body is not valid JSON for the request message: {e}")
                })?
            } else {
                // The body fills a single named field. Wrap the body
                // JSON in an object keyed by that field, then run the
                // standard proto3 JSON message decode so the field's
                // type (including nested messages) is honoured.
                let field = input.get_field_by_name(body_field).ok_or_else(|| {
                    anyhow::anyhow!("body field {body_field} not found on request message")
                })?;
                let body_value: serde_json::Value = serde_json::from_slice(body)
                    .map_err(|e| anyhow::anyhow!("request body is not valid JSON: {e}"))?;
                let wrapped = serde_json::json!({ field.json_name(): body_value });
                let wrapped_bytes = serde_json::to_vec(&wrapped)
                    .map_err(|e| anyhow::anyhow!("failed to wrap body field: {e}"))?;
                let mut de = serde_json::Deserializer::from_slice(&wrapped_bytes);
                DynamicMessage::deserialize(input.clone(), &mut de).map_err(|e| {
                    anyhow::anyhow!("request body is not valid JSON for field {body_field}: {e}")
                })?
            }
        };

        apply_path_bindings(&mut message, &bindings)?;
        apply_query_params(&mut message, path)?;

        let body_bytes = message.encode_to_vec();
        Ok(Some(TranscodedRequest {
            grpc_path: Self::grpc_path(&descriptor),
            framed_body: frame::encode_message(&body_bytes),
        }))
    }

    /// Transcode a unary gRPC response back into an HTTP/JSON response.
    ///
    /// `grpc_method` identifies the method (so the response message type
    /// is known), `frame_bytes` is the length-prefixed gRPC response
    /// frame (may be empty on an error-only response), `grpc_status` is
    /// the integer from the `grpc-status` trailer, and `grpc_message` is
    /// the human-readable `grpc-message` trailer (if any).
    pub fn transcode_response(
        &self,
        grpc_method: &str,
        frame_bytes: &[u8],
        grpc_status: i32,
        grpc_message: Option<&str>,
    ) -> anyhow::Result<TranscodedResponse> {
        let status = GrpcStatus::from_code(grpc_status);
        if status != GrpcStatus::Ok {
            return Ok(TranscodedResponse {
                http_status: status.to_http_status(),
                json_body: error_envelope(status, grpc_message),
            });
        }

        let descriptor = Self::lookup_method(&self.pool, grpc_method)?;
        let output = descriptor.output();

        if frame_bytes.is_empty() {
            // OK status with no body: emit an empty JSON object.
            return Ok(TranscodedResponse {
                http_status: 200,
                json_body: b"{}".to_vec(),
            });
        }

        let (parsed, _) = frame::decode_one(frame_bytes)?;
        let message = DynamicMessage::decode(output.clone(), parsed.payload.as_slice())
            .map_err(|e| anyhow::anyhow!("failed to decode gRPC response message: {e}"))?;

        // proto3 JSON mapping: emit default values so REST clients see a
        // stable shape rather than fields silently dropped at their
        // zero value.
        let opts = SerializeOptions::new().skip_default_fields(false);
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::new(&mut buf);
        message
            .serialize_with_options(&mut ser, &opts)
            .map_err(|e| anyhow::anyhow!("failed to serialize gRPC response to JSON: {e}"))?;
        Ok(TranscodedResponse {
            http_status: 200,
            json_body: buf,
        })
    }
}

/// Build the JSON error envelope returned for a non-OK gRPC status.
fn error_envelope(status: GrpcStatus, message: Option<&str>) -> Vec<u8> {
    let body = serde_json::json!({
        "code": status.code(),
        "status": status.name(),
        "message": message.unwrap_or(status.name()),
    });
    serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec())
}

/// Merge captured path bindings into the request message. Each binding
/// key is a (possibly dotted) field path; the value is set as a string,
/// which prost-reflect coerces to the field's scalar type.
fn apply_path_bindings(
    message: &mut DynamicMessage,
    bindings: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    for (field_path, value) in bindings {
        set_field_path(message, field_path, value)?;
    }
    Ok(())
}

/// Merge query-string parameters into the request message. Only simple
/// top-level scalar fields are supported here, which covers the common
/// transcoding case; nested fields via dotted query keys are also
/// handled by [`set_field_path`].
fn apply_query_params(message: &mut DynamicMessage, path: &str) -> anyhow::Result<()> {
    let query = match path.split_once('?') {
        Some((_, q)) => q,
        None => return Ok(()),
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let decoded = percent_decode(value);
        // Query parameters are best-effort: an unknown key is ignored
        // rather than failing the request, matching grpc-gateway.
        let _ = set_field_path(message, key, &decoded);
    }
    Ok(())
}

/// Set a (possibly dotted) field path on a dynamic message to a string
/// value, coercing the string into the field's scalar kind.
fn set_field_path(
    message: &mut DynamicMessage,
    field_path: &str,
    value: &str,
) -> anyhow::Result<()> {
    let mut parts = field_path.split('.').peekable();
    let head = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty field path"))?;
    let field = match message.descriptor().get_field_by_name(head) {
        Some(f) => f,
        None => return Ok(()), // unknown field: ignore (query best-effort)
    };

    if parts.peek().is_none() {
        let coerced = coerce_scalar(&field.kind(), value)?;
        message.set_field(&field, coerced);
        return Ok(());
    }

    // Descend into a nested message field.
    let rest: String = parts.collect::<Vec<_>>().join(".");
    let mut nested = match message.get_field(&field).as_message() {
        Some(m) => m.clone(),
        None => {
            let kind = field.kind();
            let msg_desc = kind
                .as_message()
                .ok_or_else(|| anyhow::anyhow!("field {head} is not a message; cannot descend"))?;
            DynamicMessage::new(msg_desc.clone())
        }
    };
    set_field_path(&mut nested, &rest, value)?;
    message.set_field(&field, prost_reflect::Value::Message(nested));
    Ok(())
}

/// Coerce a string (from a path binding or query parameter) into a
/// prost-reflect [`prost_reflect::Value`] of the given field kind.
fn coerce_scalar(kind: &prost_reflect::Kind, raw: &str) -> anyhow::Result<prost_reflect::Value> {
    use prost_reflect::{Kind, Value};
    let value = match kind {
        Kind::String => Value::String(raw.to_string()),
        Kind::Bool => Value::Bool(matches!(raw, "true" | "1" | "TRUE" | "True")),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Value::I32(
            raw.parse()
                .map_err(|_| anyhow::anyhow!("invalid int32 path value: {raw}"))?,
        ),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Value::I64(
            raw.parse()
                .map_err(|_| anyhow::anyhow!("invalid int64 path value: {raw}"))?,
        ),
        Kind::Uint32 | Kind::Fixed32 => Value::U32(
            raw.parse()
                .map_err(|_| anyhow::anyhow!("invalid uint32 path value: {raw}"))?,
        ),
        Kind::Uint64 | Kind::Fixed64 => Value::U64(
            raw.parse()
                .map_err(|_| anyhow::anyhow!("invalid uint64 path value: {raw}"))?,
        ),
        Kind::Float => Value::F32(
            raw.parse()
                .map_err(|_| anyhow::anyhow!("invalid float path value: {raw}"))?,
        ),
        Kind::Double => Value::F64(
            raw.parse()
                .map_err(|_| anyhow::anyhow!("invalid double path value: {raw}"))?,
        ),
        other => anyhow::bail!("unsupported field kind for path binding: {other:?}"),
    };
    Ok(value)
}

/// Minimal percent-decoding for query-parameter values (`%XX` octets
/// and `+` as space). Avoids pulling a dependency for this small need.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_reflect::{DescriptorPool, DynamicMessage};
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MethodDescriptorProto, ServiceDescriptorProto,
    };

    /// Build a small `FileDescriptorSet` covering the messages and the
    /// `Echo` service used by the transcode tests:
    ///
    /// ```proto
    /// package sbproxy_test;
    /// message EchoRequest { string message = 1; int32 count = 2; }
    /// message EchoResponse { string message = 1; int32 count = 2; }
    /// service Echo { rpc Hello(EchoRequest) returns (EchoResponse); }
    /// ```
    fn echo_descriptor_set() -> Vec<u8> {
        fn field(name: &str, number: i32, ty: Type) -> FieldDescriptorProto {
            FieldDescriptorProto {
                name: Some(name.to_string()),
                number: Some(number),
                label: Some(Label::Optional as i32),
                r#type: Some(ty as i32),
                json_name: Some(name.to_string()),
                ..Default::default()
            }
        }
        let echo_request = DescriptorProto {
            name: Some("EchoRequest".to_string()),
            field: vec![
                field("message", 1, Type::String),
                field("count", 2, Type::Int32),
            ],
            ..Default::default()
        };
        let echo_response = DescriptorProto {
            name: Some("EchoResponse".to_string()),
            field: vec![
                field("message", 1, Type::String),
                field("count", 2, Type::Int32),
            ],
            ..Default::default()
        };
        let service = ServiceDescriptorProto {
            name: Some("Echo".to_string()),
            method: vec![MethodDescriptorProto {
                name: Some("Hello".to_string()),
                input_type: Some(".sbproxy_test.EchoRequest".to_string()),
                output_type: Some(".sbproxy_test.EchoResponse".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("echo.proto".to_string()),
            package: Some("sbproxy_test".to_string()),
            syntax: Some("proto3".to_string()),
            message_type: vec![echo_request, echo_response],
            service: vec![service],
            ..Default::default()
        };
        FileDescriptorSet { file: vec![file] }.encode_to_vec()
    }

    /// Encode an `EchoResponse` as a native gRPC response frame so the
    /// response-direction tests have a realistic upstream payload.
    fn echo_response_frame(set: &[u8], message: &str, count: i32) -> Vec<u8> {
        let pool = DescriptorPool::decode(set).unwrap();
        let desc = pool
            .get_message_by_name("sbproxy_test.EchoResponse")
            .unwrap();
        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name("message", prost_reflect::Value::String(message.to_string()));
        msg.set_field_by_name("count", prost_reflect::Value::I32(count));
        frame::encode_message(&msg.encode_to_vec())
    }

    fn echo_route() -> RouteSpec {
        RouteSpec {
            method: HttpMethod::Post,
            path_template: "/v1/echo".to_string(),
            grpc_method: "sbproxy_test.Echo.Hello".to_string(),
            body: None,
        }
    }

    #[test]
    fn build_rejects_unknown_method() {
        let set = echo_descriptor_set();
        let route = RouteSpec {
            method: HttpMethod::Post,
            path_template: "/v1/echo".to_string(),
            grpc_method: "sbproxy_test.Echo.NoSuchMethod".to_string(),
            body: None,
        };
        assert!(Transcoder::from_descriptor_set(&set, &[route]).is_err());
    }

    #[test]
    fn build_rejects_bad_descriptor_set() {
        assert!(Transcoder::from_descriptor_set(b"not a descriptor", &[echo_route()]).is_err());
    }

    #[test]
    fn transcode_request_maps_json_body_to_grpc_frame() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let out = t
            .transcode_request("POST", "/v1/echo", br#"{"message":"hi","count":7}"#)
            .unwrap()
            .expect("route should match");
        assert_eq!(out.grpc_path, "/sbproxy_test.Echo/Hello");

        // The framed body must decode back to the same message.
        let (parsed, _) = frame::decode_one(&out.framed_body).unwrap();
        let pool = DescriptorPool::decode(&set[..]).unwrap();
        let desc = pool
            .get_message_by_name("sbproxy_test.EchoRequest")
            .unwrap();
        let msg = DynamicMessage::decode(desc, parsed.payload.as_slice()).unwrap();
        assert_eq!(
            msg.get_field_by_name("message").unwrap().as_str().unwrap(),
            "hi"
        );
        assert_eq!(msg.get_field_by_name("count").unwrap().as_i32().unwrap(), 7);
    }

    #[test]
    fn transcode_request_returns_none_when_no_route_matches() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        // Wrong method.
        assert!(t
            .transcode_request("GET", "/v1/echo", b"{}")
            .unwrap()
            .is_none());
        // Wrong path.
        assert!(t
            .transcode_request("POST", "/v1/nope", b"{}")
            .unwrap()
            .is_none());
    }

    #[test]
    fn transcode_request_binds_path_variable() {
        let set = echo_descriptor_set();
        let route = RouteSpec {
            method: HttpMethod::Get,
            path_template: "/v1/echo/{message}".to_string(),
            grpc_method: "sbproxy_test.Echo.Hello".to_string(),
            body: None,
        };
        let t = Transcoder::from_descriptor_set(&set, &[route]).unwrap();
        let out = t
            .transcode_request("GET", "/v1/echo/from-path", b"")
            .unwrap()
            .expect("route should match");
        let (parsed, _) = frame::decode_one(&out.framed_body).unwrap();
        let pool = DescriptorPool::decode(&set[..]).unwrap();
        let desc = pool
            .get_message_by_name("sbproxy_test.EchoRequest")
            .unwrap();
        let msg = DynamicMessage::decode(desc, parsed.payload.as_slice()).unwrap();
        assert_eq!(
            msg.get_field_by_name("message").unwrap().as_str().unwrap(),
            "from-path"
        );
    }

    #[test]
    fn transcode_request_merges_query_params() {
        let set = echo_descriptor_set();
        let route = RouteSpec {
            method: HttpMethod::Get,
            path_template: "/v1/echo".to_string(),
            grpc_method: "sbproxy_test.Echo.Hello".to_string(),
            body: None,
        };
        let t = Transcoder::from_descriptor_set(&set, &[route]).unwrap();
        let out = t
            .transcode_request("GET", "/v1/echo?message=q%20val&count=42", b"")
            .unwrap()
            .expect("route should match");
        let (parsed, _) = frame::decode_one(&out.framed_body).unwrap();
        let pool = DescriptorPool::decode(&set[..]).unwrap();
        let desc = pool
            .get_message_by_name("sbproxy_test.EchoRequest")
            .unwrap();
        let msg = DynamicMessage::decode(desc, parsed.payload.as_slice()).unwrap();
        assert_eq!(
            msg.get_field_by_name("message").unwrap().as_str().unwrap(),
            "q val"
        );
        assert_eq!(
            msg.get_field_by_name("count").unwrap().as_i32().unwrap(),
            42
        );
    }

    #[test]
    fn transcode_request_rejects_invalid_json() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        assert!(t
            .transcode_request("POST", "/v1/echo", b"not json")
            .is_err());
    }

    #[test]
    fn transcode_response_maps_grpc_message_to_json() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let frame_bytes = echo_response_frame(&set, "pong", 3);
        let resp = t
            .transcode_response("sbproxy_test.Echo.Hello", &frame_bytes, 0, None)
            .unwrap();
        assert_eq!(resp.http_status, 200);
        let json: serde_json::Value = serde_json::from_slice(&resp.json_body).unwrap();
        assert_eq!(json["message"], "pong");
        assert_eq!(json["count"], 3);
    }

    #[test]
    fn transcode_response_maps_grpc_error_to_http_status() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        // grpc-status 5 (NOT_FOUND) -> HTTP 404, body carries the envelope.
        let resp = t
            .transcode_response("sbproxy_test.Echo.Hello", &[], 5, Some("missing"))
            .unwrap();
        assert_eq!(resp.http_status, 404);
        let json: serde_json::Value = serde_json::from_slice(&resp.json_body).unwrap();
        assert_eq!(json["code"], 5);
        assert_eq!(json["status"], "NOT_FOUND");
        assert_eq!(json["message"], "missing");
    }

    #[test]
    fn transcode_response_empty_ok_body_is_empty_object() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let resp = t
            .transcode_response("sbproxy_test.Echo.Hello", &[], 0, None)
            .unwrap();
        assert_eq!(resp.http_status, 200);
        assert_eq!(resp.json_body, b"{}");
    }

    #[test]
    fn full_roundtrip_request_then_response() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();

        // 1. REST -> gRPC.
        let req = t
            .transcode_request("POST", "/v1/echo", br#"{"message":"ping","count":1}"#)
            .unwrap()
            .unwrap();
        let (parsed, _) = frame::decode_one(&req.framed_body).unwrap();

        // 2. Simulate an echo upstream that reflects the request back.
        let pool = DescriptorPool::decode(&set[..]).unwrap();
        let in_desc = pool
            .get_message_by_name("sbproxy_test.EchoRequest")
            .unwrap();
        let req_msg = DynamicMessage::decode(in_desc, parsed.payload.as_slice()).unwrap();
        let echoed = req_msg.get_field_by_name("message").unwrap();
        let resp_frame = echo_response_frame(&set, echoed.as_str().unwrap(), 1);

        // 3. gRPC -> REST.
        let resp = t
            .transcode_response("sbproxy_test.Echo.Hello", &resp_frame, 0, None)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp.json_body).unwrap();
        assert_eq!(json["message"], "ping");
    }

    #[test]
    fn route_count_reports_configured_routes() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route(), echo_route()]).unwrap();
        assert_eq!(t.route_count(), 2);
    }

    #[test]
    fn grpc_method_accepts_slash_form() {
        let set = echo_descriptor_set();
        let route = RouteSpec {
            method: HttpMethod::Post,
            path_template: "/v1/echo".to_string(),
            grpc_method: "sbproxy_test.Echo/Hello".to_string(),
            body: None,
        };
        let t = Transcoder::from_descriptor_set(&set, &[route]).unwrap();
        let out = t
            .transcode_request("POST", "/v1/echo", b"{}")
            .unwrap()
            .unwrap();
        assert_eq!(out.grpc_path, "/sbproxy_test.Echo/Hello");
    }
}

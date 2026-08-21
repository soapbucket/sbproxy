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

/// The result of matching a request to a transcode route, without the
/// body. Carries what the header phase needs to rewrite the upstream
/// request and to later decode the response.
#[derive(Debug, Clone)]
pub struct RouteMatch {
    /// The gRPC `:path` to send upstream, for example
    /// `/sbproxy_e2e.echo.Echo/Hello`.
    pub grpc_path: String,
    /// Fully-qualified gRPC method, for example
    /// `sbproxy_e2e.echo.Echo.Hello`.
    pub grpc_method: String,
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

    /// Match a request method + path against the configured routes
    /// without touching the body. Returns the gRPC `:path` to send
    /// upstream and the fully-qualified gRPC method, or `None` when no
    /// route matches.
    ///
    /// This is the header-phase counterpart to [`Self::transcode_request`]:
    /// the request pipeline needs the gRPC `:path` to rewrite the
    /// upstream request header before the body is available, then calls
    /// `transcode_request` with the buffered body to produce the frame.
    pub fn match_route(&self, http_method: &str, path: &str) -> Option<RouteMatch> {
        let method = HttpMethod::parse(http_method)?;
        let route = self
            .routes
            .iter()
            .find(|r| r.method == method && r.template.match_path(path).is_some())?;
        let descriptor = Self::lookup_method(&self.pool, &route.grpc_method).ok()?;
        Some(RouteMatch {
            grpc_path: Self::grpc_path(&descriptor),
            grpc_method: route.grpc_method.clone(),
        })
    }

    /// Transcode an inbound HTTP/JSON request into a unary gRPC frame.
    ///
    /// `http_method` is the request verb, `path` the request target
    /// (with or without a query string), and `body` the raw request
    /// body (empty for verbs that carry none). Three sources fill the
    /// gRPC request message and they are applied in this order: the JSON
    /// body, then the path template bindings, then the query parameters.
    ///
    /// Path bindings win outright. A query key addressing a field a
    /// binding already owns, or a parent or a child of one, is dropped
    /// silently, so `/v1/echo/allowed?message=forbidden` sends `allowed`
    /// upstream. The path is the resource name the route matched and the
    /// header-phase policies saw; letting the query restate it would put
    /// a value upstream that nothing earlier in the pipeline inspected.
    /// grpc-gateway filters the same way, through the path-parameter
    /// filter it hands `PopulateQueryParameters`.
    ///
    /// Every other query key overlays the body, and what happens to one
    /// turns on the kind of field it names. A key naming no field at
    /// all is ignored. So is a key naming a field with no single-string
    /// form to read: a `message` field, a `bytes` field, and an empty
    /// value against anything but a `string`, which is what `?count=`
    /// and a bare `?count` are. None of those ever reached the upstream,
    /// so refusing them now would turn requests this proxy served
    /// yesterday into 400s for nothing.
    ///
    /// A key naming a field that can hold a value but cannot read the
    /// spelling given is refused, because dropping it sends the
    /// upstream a message the caller never described with their filter
    /// or flag silently at its default. `?count=abc` against an `int32`
    /// is a 400, not a zero. `?dry_run=yes` against a `bool` is a 400,
    /// not a `false` that runs the job for real. An enum resolves by
    /// value name and then by number, as grpc-gateway does, so
    /// `?status=ACTIVE` and `?status=1` both land and `?status=NOPE` is
    /// refused.
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
        // One `match_path` per route, and the bindings come out of the
        // same call that decided the route. Finding the route and then
        // re-matching it to recover the captures ran the template
        // matcher twice per request and left an `expect` asserting that
        // the second call agreed with the first, which is an invariant
        // no type held.
        let Some((route, bindings)) = self.routes.iter().find_map(|r| {
            if r.method != method {
                return None;
            }
            r.template.match_path(path).map(|bindings| (r, bindings))
        }) else {
            return Ok(None);
        };

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
        apply_query_params(&mut message, path, &bindings)?;

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

/// The most dotted segments one field path may address.
///
/// [`set_field_path`] descends one stack frame and one nested-message
/// clone per segment. A path binding key comes from config, but a query
/// key is caller-supplied, and a self-referential message type is enough
/// to make every segment resolve: `google.protobuf.Struct` is one, and
/// any descriptor set that imports it carries it. Without a cap, a
/// single long query key recurses until the worker thread's stack runs
/// out, which is an abort rather than a failed request.
const MAX_FIELD_PATH_DEPTH: usize = 32;

/// The most query parameters one request may carry into the message.
///
/// Each parameter walks up to [`MAX_FIELD_PATH_DEPTH`] levels and clones
/// the nested message at every level it descends, so the work a request
/// line can buy is quadratic in the parameter count. Real transcoded
/// calls are nowhere near this; the cap only refuses the shape built to
/// spend CPU.
const MAX_QUERY_PARAMS: usize = 256;

/// Merge captured path bindings into the request message. Each binding
/// key is a (possibly dotted) field path; the value is percent-decoded
/// and set as a string, which [`coerce_scalar`] turns into the field's
/// scalar type.
fn apply_path_bindings(
    message: &mut DynamicMessage,
    bindings: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    for (field_path, value) in bindings {
        // `field_path` is the template's own capture name, so it comes
        // from config rather than from the caller and needs no
        // sanitizing on the way into the error; the value inside it
        // already went through `sanitize_for_error`. For the same
        // reason the returned flag is dropped: a capture name that
        // resolves to no field is a config mistake to catch at config
        // load, not a request to refuse.
        set_field_path(message, field_path, &percent_decode_path(value))
            .map_err(|e| anyhow::anyhow!("path binding {field_path}: {e}"))?;
    }
    Ok(())
}

/// Merge query-string parameters into the request message. Only simple
/// top-level scalar fields are supported here, which covers the common
/// transcoding case; nested fields via dotted query keys are also
/// handled by [`set_field_path`].
///
/// `bindings` are the path captures [`apply_path_bindings`] already
/// applied. A query key that addresses one of them is skipped, so the
/// query cannot restate the resource name the route matched on. See
/// [`Transcoder::transcode_request`] for why that precedence is the one
/// worth having.
fn apply_query_params(
    message: &mut DynamicMessage,
    path: &str,
    bindings: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let query = match path.split_once('?') {
        Some((_, q)) => q,
        None => return Ok(()),
    };
    let mut count = 0usize;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        count += 1;
        if count > MAX_QUERY_PARAMS {
            anyhow::bail!("query carries more than {MAX_QUERY_PARAMS} parameters");
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        // A path binding owns this field path. Skipping rather than
        // failing keeps a client that restates the resource name it
        // already put in the path working; it just does not get to
        // change it. The key is compared raw, exactly as
        // `set_field_path` would resolve it, so an encoded spelling
        // cannot slip past the skip and then hit the field anyway.
        if is_path_bound(key, bindings) {
            continue;
        }
        let decoded = percent_decode(value);
        // An unknown key is ignored rather than failing the request, and
        // so is a key naming a kind with no string form to read: see
        // [`coerce_scalar`] for which kinds those are and why refusing
        // them would be an availability regression rather than a fix.
        // What is refused is a value this transcoder can read the kind
        // of and cannot read this spelling of, because dropping that one
        // sends the upstream a message the caller never described, with
        // the filter or flag they asked for silently at its default.
        set_field_path(message, key, &decoded)
            .map_err(|e| anyhow::anyhow!("query parameter {}: {e}", sanitize_for_error(key)))?;
    }
    Ok(())
}

/// Whether a query key addresses a field path a capture already bound.
///
/// True for the same path, for a path below a binding (`a.b` is bound,
/// the key is `a.b.c`), and for a path above one (`a.b` is bound, the
/// key is `a`, which would replace the message holding it). Comparison
/// is on whole dotted segments, so a binding on `user.id` does not
/// shadow a sibling named `user.id_hint`.
///
/// The below-a-binding arm is what keeps `?user.id.deeper=x` a dropped
/// parameter instead of a 400: the walk would stop at `field id is not
/// a message; cannot descend`, and that error now propagates. The
/// above-a-binding arm changes no outcome today, because a path above a
/// binding always names a message field and [`coerce_scalar`] skips
/// those anyway. It stays because the reason it is inert is a decision
/// made one function away: give `message` a coercion later and this arm
/// is the only thing standing between a query parameter and the
/// resource name the route matched on.
fn is_path_bound(key: &str, bindings: &BTreeMap<String, String>) -> bool {
    bindings
        .keys()
        .any(|bound| key == bound || is_dotted_prefix(bound, key) || is_dotted_prefix(key, bound))
}

/// Whether `prefix` is a whole-segment dotted prefix of `path`.
fn is_dotted_prefix(prefix: &str, path: &str) -> bool {
    path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'.')
}

/// Set a (possibly dotted) field path on a dynamic message to a string
/// value, coercing the string into the field's scalar kind.
///
/// Returns whether a field was actually set. An ignored key sets
/// nothing, and the caller of the recursion needs to know that: writing
/// the parent message back after a leaf was skipped would hand the
/// upstream a present-but-empty submessage the caller never sent, which
/// an upstream `has_user()` answers yes to.
fn set_field_path(
    message: &mut DynamicMessage,
    field_path: &str,
    value: &str,
) -> anyhow::Result<bool> {
    // Checked once here rather than counted down through the recursion:
    // each level of `set_field_path_inner` consumes one segment, so a
    // path that passes this check cannot recurse deeper than it.
    let depth = field_path.split('.').count();
    if depth > MAX_FIELD_PATH_DEPTH {
        anyhow::bail!("field path is too deep: {depth} segments, limit {MAX_FIELD_PATH_DEPTH}");
    }
    set_field_path_inner(message, field_path, value)
}

/// The depth-bounded recursion behind [`set_field_path`].
fn set_field_path_inner(
    message: &mut DynamicMessage,
    field_path: &str,
    value: &str,
) -> anyhow::Result<bool> {
    let mut parts = field_path.split('.').peekable();
    let head = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty field path"))?;
    let field = match message.descriptor().get_field_by_name(head) {
        Some(f) => f,
        None => return Ok(false), // unknown field: ignore (query best-effort)
    };

    if parts.peek().is_none() {
        return Ok(match coerce_scalar(&field.kind(), value)? {
            Coerced::Set(coerced) => {
                message.set_field(&field, coerced);
                true
            }
            Coerced::Skip => false,
        });
    }

    // Descend into a nested message field.
    let rest: String = parts.collect::<Vec<_>>().join(".");
    let mut nested = match message.get_field(&field).as_message() {
        Some(m) => m.clone(),
        None => {
            let kind = field.kind();
            // The one resolution failure that refuses rather than
            // ignoring. `a.b` where `a` is a scalar is not a field this
            // transcoder happens not to support, it is a key that could
            // never name a field in any message: the caller wrote a
            // dotted path through something that has no fields. An
            // unknown *name* is ignored a few lines up, because a
            // client sending a parameter this route does not know about
            // is ordinary; a structurally impossible path is not.
            let msg_desc = kind
                .as_message()
                .ok_or_else(|| anyhow::anyhow!("field {head} is not a message; cannot descend"))?;
            DynamicMessage::new(msg_desc.clone())
        }
    };
    if !set_field_path_inner(&mut nested, &rest, value)? {
        return Ok(false);
    }
    message.set_field(&field, prost_reflect::Value::Message(nested));
    Ok(true)
}

/// What [`coerce_scalar`] decided to do with a caller-supplied string.
enum Coerced {
    /// Set the field to this value.
    Set(prost_reflect::Value),
    /// Leave the field alone and do not fail the request.
    Skip,
}

/// Coerce a string (from a path binding or query parameter) into a
/// prost-reflect [`prost_reflect::Value`] of the given field kind.
///
/// Every kind lands in one of three places, and which one it gets is
/// the decision this function exists to make. The line between the last
/// two is what keeps refusing a bad value from also refusing a shape
/// that never worked in the first place.
///
/// **Set.** `string` takes the value as it stands, empty included. The
/// ten integer kinds and the two floating-point ones parse. `bool`
/// reads the set Go's
/// `strconv.ParseBool` reads, which is the set grpc-gateway reads. An
/// enum resolves by value name and then by number.
///
/// **Refuse.** A non-empty value against a kind that can hold one and
/// cannot read this spelling: `?count=abc`, `?dry_run=yes`,
/// `?status=NOPE`. The caller named a real field and got the value
/// wrong, and dropping it would send the upstream that field at its
/// default with a 200 on top. Refusing these is the whole point of the
/// change.
///
/// **Skip.** A kind with no single-string form at all, and an empty
/// value against any kind that has to parse one:
///
/// * `message` and `bytes`. grpc-gateway reads a `bytes` field as
///   base64 and a message field through its nested leaves; neither is
///   implemented here, so there is no spelling a caller could have got
///   right. Refusing would convert "unsupported" into "rejected" for a
///   whole field kind, which is an availability regression and not a
///   fix.
/// * An empty value against any non-`string` kind, which is what
///   `?count=` and a bare `?count` decode to. HTML forms and generated
///   clients emit that routinely for a field the user left alone, and
///   it used to reach the upstream harmlessly.
///
/// There is deliberately no catch-all arm. Every [`prost_reflect::Kind`]
/// is named, so a new one is a compile error here rather than a silent
/// refusal, and no field descriptor's `Debug` can reach the 400 body the
/// way a `bail!("... {other:?}")` put one there.
///
/// Cardinality is not this function's business and is deliberately not
/// checked. A repeated field takes the coerced value as a single
/// element, and repeating the key overwrites rather than appends, which
/// is a divergence from grpc-gateway. It is also what this transcoder
/// has always done, so it stays as it is rather than being narrowed
/// here into another kind that used to work and now 400s.
fn coerce_scalar(kind: &prost_reflect::Kind, raw: &str) -> anyhow::Result<Coerced> {
    use prost_reflect::{Kind, Value};
    if raw.is_empty() && !matches!(kind, Kind::String) {
        return Ok(Coerced::Skip);
    }
    let value = match kind {
        Kind::String => Value::String(raw.to_string()),
        Kind::Bool => Value::Bool(parse_bool(raw)?),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Value::I32(parse_scalar(raw, "int32")?),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Value::I64(parse_scalar(raw, "int64")?),
        Kind::Uint32 | Kind::Fixed32 => Value::U32(parse_scalar(raw, "uint32")?),
        Kind::Uint64 | Kind::Fixed64 => Value::U64(parse_scalar(raw, "uint64")?),
        Kind::Float => Value::F32(parse_scalar(raw, "float")?),
        Kind::Double => Value::F64(parse_scalar(raw, "double")?),
        Kind::Enum(desc) => Value::EnumNumber(parse_enum(desc, raw)?),
        Kind::Message(_) | Kind::Bytes => return Ok(Coerced::Skip),
    };
    Ok(Coerced::Set(value))
}

/// Parse a caller-supplied scalar, naming the target type on failure.
/// The offending value is sanitized on the way into the error string,
/// which the 400 body reflects back.
fn parse_scalar<T: std::str::FromStr>(raw: &str, ty: &str) -> anyhow::Result<T> {
    raw.parse::<T>()
        .map_err(|_| anyhow::anyhow!("invalid {ty} value: {}", sanitize_for_error(raw)))
}

/// Read a boolean the way Go's `strconv.ParseBool` does, which is what
/// grpc-gateway calls for a `bool` query parameter.
///
/// The arm this replaces was `matches!(raw, "true" | "1" | "TRUE" |
/// "True")`, a total match with no failure path: every other spelling
/// read as `false`. `?dry_run=yes` therefore answered 200 and ran the
/// job for real, which is exactly the silent-default outcome the rest of
/// this change refuses. Every spelling that was `true` before is still
/// `true`, five more false spellings are now read rather than guessed
/// at, and anything outside the twelve is refused instead of quietly
/// becoming `false`.
fn parse_bool(raw: &str) -> anyhow::Result<bool> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        other => anyhow::bail!("invalid bool value: {}", sanitize_for_error(other)),
    }
}

/// Resolve an enum value by name, then by number.
///
/// `Kind::Enum` had no coercion at all before: it fell into the
/// catch-all bail arm, so an ordinary `?status=ACTIVE` on a
/// `google.api.http`-annotated API was dropped on the floor and the
/// upstream saw the zero value. Reading it by name and falling back to
/// the number is what grpc-gateway does, so the same request that works
/// against a grpc-gateway deployment works here.
///
/// A number that names no declared value is still accepted, because an
/// unrecognized number is a legal proto3 enum value on the wire rather
/// than an error, and range-checking here would refuse a request the
/// upstream is required to be able to parse. The enum's type name is
/// deliberately left out of the error: the 400 body reflects it, and
/// that body is not a place to publish the descriptor set's contents.
fn parse_enum(desc: &prost_reflect::EnumDescriptor, raw: &str) -> anyhow::Result<i32> {
    if let Some(value) = desc.get_value_by_name(raw) {
        return Ok(value.number());
    }
    raw.parse::<i32>()
        .map_err(|_| anyhow::anyhow!("invalid enum value: {}", sanitize_for_error(raw)))
}

/// Trim a caller-supplied string down to something safe to put in an
/// error, which is reflected in the 400 body and may reach a log line.
/// Percent-decoding turns `%0A` into a real newline, so without this a
/// query value is a log-forging primitive; the length cap keeps a
/// request-line-sized value out of the record too.
fn sanitize_for_error(raw: &str) -> String {
    const MAX: usize = 64;
    let mut out: String = raw
        .chars()
        .take(MAX)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect();
    if raw.chars().nth(MAX).is_some() {
        out.push_str("...");
    }
    out
}

/// RFC 3986 reserved characters: the gen-delims and sub-delims sets.
/// These stay percent-encoded when a captured path segment is decoded.
fn is_reserved(byte: u8) -> bool {
    b":/?#[]@!$&'()*+,;=".contains(&byte)
}

/// Minimal percent-decoding (`%XX` octets). Avoids pulling a dependency
/// for this small need.
///
/// The two flags are what separates a query value from a path capture.
/// `plus_is_space` is form encoding's `+` rule, which is a query
/// convention: a `+` in a path segment is a literal plus. `keep_reserved`
/// leaves reserved octets encoded, so a `%2F` in a capture cannot grow
/// the segment separator the template never authorized, and the value
/// the upstream receives still says what the route matched on. Envoy's
/// `grpc_json_transcoder` splits it the same way and defaults its
/// `url_unescape_spec` to `ALL_CHARACTERS_EXCEPT_RESERVED`.
fn percent_decode_with(input: &str, plus_is_space: bool, keep_reserved: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    let octet = (h * 16 + l) as u8;
                    if keep_reserved && is_reserved(octet) {
                        out.extend_from_slice(&bytes[i..i + 3]);
                    } else {
                        out.push(octet);
                    }
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

/// Percent-decode a query-parameter value (`%XX` octets, `+` as space).
fn percent_decode(input: &str) -> String {
    percent_decode_with(input, true, false)
}

/// Percent-decode a captured path segment, leaving reserved octets
/// encoded and `+` literal.
fn percent_decode_path(input: &str) -> String {
    percent_decode_with(input, false, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_reflect::{DescriptorPool, DynamicMessage};
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
        FileDescriptorProto, FileDescriptorSet, MethodDescriptorProto, ServiceDescriptorProto,
    };

    /// Build a small `FileDescriptorSet` covering the messages and the
    /// `Echo` service used by the transcode tests:
    ///
    /// ```proto
    /// package sbproxy_test;
    /// enum Status { STATUS_UNKNOWN = 0; ACTIVE = 1; RETIRED = 2; }
    /// message User { string id = 1; string id_hint = 2; bytes note = 3; }
    /// message EchoRequest {
    ///   string message = 1;
    ///   int32 count = 2;
    ///   User user = 3;
    ///   Status status = 4;
    ///   bool dry_run = 5;
    ///   bytes blob = 6;
    /// }
    /// message EchoResponse { string message = 1; int32 count = 2; }
    /// service Echo { rpc Hello(EchoRequest) returns (EchoResponse); }
    /// ```
    ///
    /// Every field past `count` earns its place by being a kind the
    /// query-parameter rules treat differently:
    ///
    /// * `User.id_hint` is the sibling that a precedence rule comparing
    ///   raw string prefixes rather than whole dotted segments would
    ///   wrongly shadow behind a `user.id` binding.
    /// * `status` is the enum, which had no coercion at all and so used
    ///   to be a 400 with an `EnumDescriptor`'s `Debug` in the body.
    /// * `dry_run` is the bool whose old arm could not fail, so
    ///   `?dry_run=yes` ran the job for real.
    /// * `blob` is `bytes`, which alongside `user` covers the two kinds
    ///   that have to be ignored rather than refused, and `User.note` is
    ///   the same kind one level down, where ignoring a leaf must not
    ///   leave its parent behind.
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
        fn message_field(name: &str, number: i32, type_name: &str) -> FieldDescriptorProto {
            FieldDescriptorProto {
                type_name: Some(type_name.to_string()),
                ..field(name, number, Type::Message)
            }
        }
        fn enum_field(name: &str, number: i32, type_name: &str) -> FieldDescriptorProto {
            FieldDescriptorProto {
                type_name: Some(type_name.to_string()),
                ..field(name, number, Type::Enum)
            }
        }
        fn enum_value(name: &str, number: i32) -> EnumValueDescriptorProto {
            EnumValueDescriptorProto {
                name: Some(name.to_string()),
                number: Some(number),
                ..Default::default()
            }
        }
        let status = EnumDescriptorProto {
            name: Some("Status".to_string()),
            value: vec![
                enum_value("STATUS_UNKNOWN", 0),
                enum_value("ACTIVE", 1),
                enum_value("RETIRED", 2),
            ],
            ..Default::default()
        };
        let user = DescriptorProto {
            name: Some("User".to_string()),
            field: vec![
                field("id", 1, Type::String),
                field("id_hint", 2, Type::String),
                field("note", 3, Type::Bytes),
            ],
            ..Default::default()
        };
        let echo_request = DescriptorProto {
            name: Some("EchoRequest".to_string()),
            field: vec![
                field("message", 1, Type::String),
                field("count", 2, Type::Int32),
                message_field("user", 3, ".sbproxy_test.User"),
                enum_field("status", 4, ".sbproxy_test.Status"),
                field("dry_run", 5, Type::Bool),
                field("blob", 6, Type::Bytes),
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
            message_type: vec![user, echo_request, echo_response],
            enum_type: vec![status],
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

    /// A route whose capture binds a nested field path.
    fn user_route() -> RouteSpec {
        RouteSpec {
            method: HttpMethod::Get,
            path_template: "/v1/users/{user.id}".to_string(),
            grpc_method: "sbproxy_test.Echo.Hello".to_string(),
            body: None,
        }
    }

    /// A route whose capture binds a single top-level field.
    fn echo_path_route() -> RouteSpec {
        RouteSpec {
            method: HttpMethod::Get,
            path_template: "/v1/echo/{message}".to_string(),
            grpc_method: "sbproxy_test.Echo.Hello".to_string(),
            body: None,
        }
    }

    /// Decode a transcoded request frame back into its `EchoRequest`.
    fn decode_request(set: &[u8], framed: &[u8]) -> DynamicMessage {
        let (parsed, _) = frame::decode_one(framed).unwrap();
        let pool = DescriptorPool::decode(set).unwrap();
        let desc = pool
            .get_message_by_name("sbproxy_test.EchoRequest")
            .unwrap();
        DynamicMessage::decode(desc, parsed.payload.as_slice()).unwrap()
    }

    /// The top-level `message` field of a decoded request.
    fn message_of(msg: &DynamicMessage) -> String {
        msg.get_field_by_name("message")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }

    /// The top-level `count` field of a decoded request.
    fn count_of(msg: &DynamicMessage) -> i32 {
        msg.get_field_by_name("count").unwrap().as_i32().unwrap()
    }

    /// The top-level `status` enum field, as its wire number.
    fn status_of(msg: &DynamicMessage) -> i32 {
        msg.get_field_by_name("status")
            .unwrap()
            .as_enum_number()
            .unwrap()
    }

    /// A named top-level `bool` field of a decoded request.
    fn bool_of(msg: &DynamicMessage, name: &str) -> bool {
        msg.get_field_by_name(name).unwrap().as_bool().unwrap()
    }

    /// A named string field of the nested `user` message.
    fn user_field_of(msg: &DynamicMessage, name: &str) -> String {
        let user = msg.get_field_by_name("user").unwrap();
        let nested = user.as_message().unwrap();
        nested
            .get_field_by_name(name)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
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

    /// The call the defect showed up on. `match_path` strips the query
    /// before matching, so `/v1/echo/allowed?message=forbidden` routes
    /// and binds on `allowed`, and the query parameter then used to
    /// overwrite it: the value the route matched on and the value the
    /// upstream received were different strings.
    #[test]
    fn transcode_request_query_cannot_override_path_binding() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_path_route()]).unwrap();
        let out = t
            .transcode_request("GET", "/v1/echo/allowed?message=forbidden", b"")
            .unwrap()
            .expect("route should match");
        assert_eq!(
            message_of(&decode_request(&set, &out.framed_body)),
            "allowed"
        );
    }

    #[test]
    fn transcode_request_query_cannot_override_a_nested_path_binding() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[user_route()]).unwrap();
        let out = t
            .transcode_request(
                "GET",
                "/v1/users/bound?user.id=forbidden&user.id_hint=kept",
                b"",
            )
            .unwrap()
            .expect("route should match");
        let msg = decode_request(&set, &out.framed_body);
        assert_eq!(user_field_of(&msg, "id"), "bound");
        // The sibling still applies: the skip compares whole dotted
        // segments, so `user.id` does not shadow `user.id_hint`.
        assert_eq!(user_field_of(&msg, "id_hint"), "kept");
    }

    /// The three arms of the precedence rule and the two shapes it must
    /// not catch, asserted on the predicate itself.
    ///
    /// This replaces an end-to-end test of the above-a-binding arm. That
    /// test could not fail: a path above a binding always names a
    /// message field, [`coerce_scalar`] skips message fields, and the
    /// old code discarded the error it used to raise, so the binding
    /// survived `?user=forbidden` with the arm, without the arm, and on
    /// the code before the change. Here each line is the only thing that
    /// fails if its arm is deleted.
    #[test]
    fn is_path_bound_matches_the_path_its_parents_and_its_children_only() {
        let bindings: BTreeMap<String, String> = [("user.id".to_string(), "bound".to_string())]
            .into_iter()
            .collect();
        assert!(is_path_bound("user.id", &bindings), "the bound path itself");
        assert!(is_path_bound("user", &bindings), "a parent of the binding");
        assert!(
            is_path_bound("user.id.deeper", &bindings),
            "a child of the binding"
        );
        assert!(
            !is_path_bound("user.id_hint", &bindings),
            "a sibling sharing a string prefix with the binding"
        );
        assert!(
            !is_path_bound("users", &bindings),
            "an unrelated key sharing a string prefix"
        );
        assert!(!is_path_bound("message", &bindings), "an unrelated key");
    }

    /// `?user.id.deeper=x` addresses below the `user.id` binding. The
    /// walk stops at `field id is not a message; cannot descend`, and
    /// this change propagates that error, so without the skip the whole
    /// request would be a 400 rather than one dropped parameter. The
    /// sibling in the same query proves the skip stays narrow.
    #[test]
    fn transcode_request_query_cannot_address_below_a_binding() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[user_route()]).unwrap();
        let out = t
            .transcode_request(
                "GET",
                "/v1/users/bound?user.id.deeper=forbidden&user.id_hint=kept",
                b"",
            )
            .expect("a key below a binding is dropped, not refused")
            .expect("route should match");
        let msg = decode_request(&set, &out.framed_body);
        assert_eq!(user_field_of(&msg, "id"), "bound");
        assert_eq!(user_field_of(&msg, "id_hint"), "kept");
    }

    #[test]
    fn transcode_request_percent_decodes_a_path_binding() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_path_route()]).unwrap();
        let out = t
            .transcode_request("GET", "/v1/echo/all%6Fwed", b"")
            .unwrap()
            .expect("route should match");
        assert_eq!(
            message_of(&decode_request(&set, &out.framed_body)),
            "allowed"
        );
    }

    /// `%2F` stays encoded so a single-segment capture cannot grow the
    /// separator the template never authorized, and `+` stays a literal
    /// plus, which is what it means in a path even though a query value
    /// reads it as a space.
    ///
    /// The mixed case carries the test. `a%2Fb+c` alone is the same
    /// string whether reserved octets are kept or nothing is decoded at
    /// all, so it cannot tell this rule from the old no-decoding
    /// behavior; `a%2Fb%20c` decoding to `a%2Fb c` distinguishes the two
    /// in one assertion.
    #[test]
    fn transcode_request_keeps_reserved_octets_in_a_path_binding() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_path_route()]).unwrap();
        for (target, expected) in [
            ("/v1/echo/a%2Fb+c", "a%2Fb+c"),
            ("/v1/echo/a%2Fb%20c", "a%2Fb c"),
        ] {
            let out = t
                .transcode_request("GET", target, b"")
                .unwrap()
                .expect("route should match");
            let msg = decode_request(&set, &out.framed_body);
            assert_eq!(message_of(&msg), expected, "{target}");
        }
    }

    /// Dropping the parameter would send the upstream a message the
    /// caller never described, with `count` sitting at its default. The
    /// reflected value is sanitized on the way out: `%0A` decodes to a
    /// real newline, and the error string reaches the 400 body.
    #[test]
    fn transcode_request_refuses_an_uncoercible_query_value() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let err = t
            .transcode_request("POST", "/v1/echo?count=1%0Aforged", b"{}")
            .unwrap_err()
            .to_string();
        assert!(err.contains("query parameter count"), "unexpected: {err}");
        assert!(err.contains("1?forged"), "unexpected: {err}");
        assert!(!err.contains('\n'), "control byte reflected: {err:?}");
    }

    /// `?count=` and a bare `?count` are what an HTML form and a
    /// generated client emit for a field the caller left alone. Both
    /// reached the upstream harmlessly before this change, and refusing
    /// a value that carries no information is a refusal the fix never
    /// needed.
    #[test]
    fn transcode_request_ignores_an_empty_query_value() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        for target in ["/v1/echo?count=", "/v1/echo?count"] {
            let out = t
                .transcode_request("POST", target, b"{}")
                .expect("an empty value is dropped, not refused")
                .expect("route should match");
            let msg = decode_request(&set, &out.framed_body);
            assert_eq!(count_of(&msg), 0, "{target}");
        }

        // An empty value does not swallow the rest of the query.
        let out = t
            .transcode_request("POST", "/v1/echo?count=&message=kept", b"{}")
            .unwrap()
            .expect("route should match");
        let msg = decode_request(&set, &out.framed_body);
        assert_eq!(message_of(&msg), "kept");
    }

    /// A `message` field and a `bytes` field have no single-string form
    /// this transcoder reads, so a query key naming one never worked.
    /// Refusing it would turn "silently unsupported" into "rejected" for
    /// a whole field kind, which is an availability regression rather
    /// than a fix. The catch-all arm that used to raise the error also
    /// put the field descriptor's `Debug` into the reflected 400 body.
    #[test]
    fn transcode_request_ignores_a_query_key_naming_a_message_or_bytes_field() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let out = t
            .transcode_request("POST", "/v1/echo?user=x&blob=y&message=kept", b"{}")
            .expect("an unreadable field kind is dropped, not refused")
            .expect("route should match");
        let msg = decode_request(&set, &out.framed_body);
        assert_eq!(message_of(&msg), "kept");
        assert_eq!(user_field_of(&msg, "id"), "");
        assert!(msg
            .get_field_by_name("blob")
            .unwrap()
            .as_bytes()
            .unwrap()
            .is_empty());
    }

    /// Ignoring a leaf must not create the message that would have held
    /// it. `?user.note=x` names a `bytes` field, so nothing is set, and
    /// writing `user` back regardless would hand the upstream a
    /// present-but-empty `User` the caller never sent, which an upstream
    /// `has_user()` answers yes to. `?user.nope=y` is the same shape for
    /// a name that resolves to no field at all.
    #[test]
    fn transcode_request_does_not_create_a_parent_for_an_ignored_leaf() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let out = t
            .transcode_request("POST", "/v1/echo?user.note=x&user.nope=y", b"{}")
            .expect("an ignored leaf is dropped, not refused")
            .expect("route should match");
        let msg = decode_request(&set, &out.framed_body);
        assert!(!msg.has_field_by_name("user"), "phantom parent message");

        // A leaf that does land still creates it.
        let out = t
            .transcode_request("POST", "/v1/echo?user.id=real", b"{}")
            .unwrap()
            .expect("route should match");
        let msg = decode_request(&set, &out.framed_body);
        assert!(msg.has_field_by_name("user"));
        assert_eq!(user_field_of(&msg, "id"), "real");
    }

    /// `Kind::Enum` had no coercion at all, so an ordinary
    /// `?status=ACTIVE` on a `google.api.http`-annotated API fell into
    /// the catch-all arm: dropped before this change, and a 400 carrying
    /// an `EnumDescriptor`'s `Debug` after the first cut of it. Reading
    /// the name and falling back to the number is what grpc-gateway
    /// does, so a request that works against a grpc-gateway deployment
    /// works here.
    #[test]
    fn transcode_request_reads_an_enum_query_value_by_name_then_by_number() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        for (target, expected) in [
            ("/v1/echo?status=ACTIVE", 1),
            ("/v1/echo?status=RETIRED", 2),
            ("/v1/echo?status=2", 2),
            // Proto3 keeps an unrecognized enum number on the wire
            // rather than refusing it, so a number outside the declared
            // set is not range-checked here either.
            ("/v1/echo?status=77", 77),
        ] {
            let out = t
                .transcode_request("POST", target, b"{}")
                .expect("a readable enum value is not refused")
                .expect("route should match");
            let msg = decode_request(&set, &out.framed_body);
            assert_eq!(status_of(&msg), expected, "{target}");
        }
    }

    /// A spelling that is neither a declared value name nor a number is
    /// refused, because the caller named a real field and the upstream
    /// would otherwise see the enum's zero value under a 200. The
    /// descriptor's type name stays out of the reflected body.
    #[test]
    fn transcode_request_refuses_an_unreadable_enum_query_value() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let err = t
            .transcode_request("POST", "/v1/echo?status=NOPE", b"{}")
            .unwrap_err()
            .to_string();
        assert!(err.contains("query parameter status"), "unexpected: {err}");
        assert!(
            err.contains("invalid enum value: NOPE"),
            "unexpected: {err}"
        );
        assert!(!err.contains("sbproxy_test"), "schema reflected: {err}");
    }

    /// The old bool arm was a total `matches!`, so every spelling it did
    /// not list read as `false` under a 200: `?dry_run=yes` ran the job
    /// for real. The accepted set is Go's `strconv.ParseBool`, which is
    /// the set grpc-gateway reads, so nothing that used to be `true`
    /// changed and five more `false` spellings are now read rather than
    /// guessed at.
    #[test]
    fn transcode_request_reads_the_accepted_bool_spellings_and_refuses_the_rest() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let read = |raw: &str| {
            let out = t
                .transcode_request("POST", &format!("/v1/echo?dry_run={raw}"), b"{}")
                .unwrap_or_else(|e| panic!("{raw} should be readable: {e}"))
                .expect("route should match");
            bool_of(&decode_request(&set, &out.framed_body), "dry_run")
        };
        for raw in ["1", "t", "T", "TRUE", "true", "True"] {
            assert!(read(raw), "{raw} should read as true");
        }
        for raw in ["0", "f", "F", "FALSE", "false", "False"] {
            assert!(!read(raw), "{raw} should read as false");
        }
        for raw in ["yes", "on", "y", "TrUe", "1.0"] {
            let err = t
                .transcode_request("POST", &format!("/v1/echo?dry_run={raw}"), b"{}")
                .unwrap_err()
                .to_string();
            assert!(err.contains("invalid bool value"), "{raw}: {err}");
        }
    }

    #[test]
    fn transcode_request_refuses_more_query_params_than_the_cap() {
        let set = echo_descriptor_set();
        let t = Transcoder::from_descriptor_set(&set, &[echo_route()]).unwrap();
        let query = |n: usize| {
            let pairs: Vec<String> = (0..n).map(|i| format!("k{i}=1")).collect();
            format!("/v1/echo?{}", pairs.join("&"))
        };
        assert!(t
            .transcode_request("POST", &query(MAX_QUERY_PARAMS), b"{}")
            .unwrap()
            .is_some());
        assert!(t
            .transcode_request("POST", &query(MAX_QUERY_PARAMS + 1), b"{}")
            .is_err());
    }

    /// A self-referential message type makes every segment of a dotted
    /// key resolve, so without the cap a long enough query key recurses
    /// until the worker thread's stack runs out, which aborts the process
    /// rather than failing the request.
    #[test]
    fn set_field_path_refuses_an_over_deep_field_path() {
        let set = echo_descriptor_set();
        let pool = DescriptorPool::decode(&set[..]).unwrap();
        let desc = pool
            .get_message_by_name("sbproxy_test.EchoRequest")
            .unwrap();
        let mut msg = DynamicMessage::new(desc);

        let too_deep = ["user"; MAX_FIELD_PATH_DEPTH + 1].join(".");
        let err = set_field_path(&mut msg, &too_deep, "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("too deep"), "unexpected: {err}");

        // At the limit the cap does not fire; that walk ends on its own
        // because `User` has no `user` field of its own.
        let at_limit = ["user"; MAX_FIELD_PATH_DEPTH].join(".");
        assert!(set_field_path(&mut msg, &at_limit, "x").is_ok());
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

//! gRPC transcoding and gRPC-Web bridging for the transport layer.
//!
//! This module gives the proxy three capabilities on top of the
//! transparent gRPC passthrough that the `grpc` action already provides:
//!
//! - [`Transcoder`]: descriptor-driven REST <-> gRPC transcoding. A JSON
//!   HTTP request is mapped to a unary gRPC call (driven by a protobuf
//!   `FileDescriptorSet` plus `google.api.http`-style path templates) and
//!   the gRPC response is mapped back to JSON.
//! - [`GrpcWebBridge`]: bridges a browser gRPC-Web client (HTTP/1.1 with
//!   base64 or binary framing, trailers folded into the body) to a native
//!   gRPC upstream, for unary and server-streaming calls.
//! - [`GrpcStatus`]: the canonical gRPC status codes and their mapping to
//!   and from HTTP status codes, used by both of the above.
//!
//! These pieces are pure, allocation-light helpers with no I/O so they
//! unit-test cleanly; the request pipeline calls them to rewrite bodies
//! while Pingora carries the bytes.
//!
//! ## HTTP/3 capability
//!
//! Transcoding and gRPC-Web bridging are driven from the HTTP/1.1 and
//! HTTP/2 request path. gRPC itself mandates HTTP/2 end-to-end to the
//! upstream, and the `grpc` action is documented as unsupported over the
//! proxy's HTTP/3 listener (it returns `501` there). These helpers do not
//! change that: an HTTP/3 inbound request is not transcoded.

pub mod frame;
pub mod status;
pub mod template;
pub mod transcode;
pub mod web;

pub use frame::{decode_all, decode_one, encode_message, Frame};
pub use status::GrpcStatus;
pub use template::PathTemplate;
pub use transcode::{HttpMethod, RouteSpec, TranscodedRequest, TranscodedResponse, Transcoder};
pub use web::{is_grpc_web, is_text_encoded, GrpcTrailers, GrpcWebBridge};

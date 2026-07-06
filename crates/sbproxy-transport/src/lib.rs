//! sbproxy-transport: Custom HTTP transport features.
//!
//! Provides the gRPC surface for the proxy transport layer: gRPC-Web
//! bridging and descriptor-driven REST <-> gRPC transcoding.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod grpc;

pub use grpc::{
    GrpcStatus, GrpcTrailers, GrpcWebBridge, HttpMethod, PathTemplate, RouteSpec,
    TranscodedRequest, TranscodedResponse, Transcoder,
};

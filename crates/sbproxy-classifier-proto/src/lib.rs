//! Generated gRPC types for the sbproxy classifier `InferenceService` (WOR-704).
//!
//! This crate is nothing but the compiled, self-contained `classifier.proto`
//! contract: the tonic client the proxy uses and the tonic server the OSS
//! minimal sidecar (and the enterprise rich sidecar) implement. Keeping it as
//! its own crate means the proto is the single shared artifact between the two
//! sidecars without either depending on the other.
//!
//! The generated code carries no doc comments and trips several pedantic
//! clippy lints, so the wrapping module suppresses both; everything below it
//! is machine-generated from the proto.

/// Generated types for package `sbproxy.classifier.v1`.
#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod v1 {
    tonic::include_proto!("sbproxy.classifier.v1");
}

pub use v1::inference_service_client::InferenceServiceClient;
pub use v1::inference_service_server::{InferenceService, InferenceServiceServer};
pub use v1::{
    ClassifyRequest, ClassifyResponse, EmbedRequest, EmbedResponse, Embedding, Label,
    ModelInfoRequest, ModelInfoResponse, VersionRequest, VersionResponse,
};

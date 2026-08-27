//! Generated gRPC types for the sbproxy classifier `InferenceService` and
//! `ClassifierService`.
//!
//! This crate is nothing but the compiled, self-contained `classifier.proto`
//! contract: the tonic clients the proxy and `sbproxy-classifier-client` use,
//! and the tonic servers the OSS minimal sidecar (`InferenceService` only)
//! and the enterprise rich sidecar (`sbproxy-classifier`, both services)
//! implement. Keeping it as its own crate means the proto is the single
//! shared artifact between the sidecars without either depending on the
//! other.
//!
//! `InferenceService` is the contract both sidecars serve. `ClassifierService`
//! (WOR-2665) is additional surface only `sbproxy-classifier` serves: a
//! caller that only ever talks to the minimal sidecar never constructs a
//! `ClassifierServiceClient`, so this costs nothing when unused.
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
    compress_request, ClassifyRequest, ClassifyResponse, CompressRequest, CompressResponse,
    EmbedRequest, EmbedResponse, Embedding, Label, ModelInfoRequest, ModelInfoResponse,
    VersionRequest, VersionResponse,
};

pub use v1::classifier_service_client::ClassifierServiceClient;
pub use v1::classifier_service_server::{ClassifierService, ClassifierServiceServer};
pub use v1::{QualityRequest, QualityResponse, SafetyToken, SafetyVerdict};

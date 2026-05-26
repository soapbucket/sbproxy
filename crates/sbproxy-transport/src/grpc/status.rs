//! gRPC status code definitions and the gRPC <-> HTTP status mapping.
//!
//! gRPC carries its own status namespace (the canonical codes 0 to 16)
//! in the `grpc-status` trailer, separate from the HTTP/2 `:status`
//! pseudo-header (which is almost always 200 for a well-formed gRPC
//! call). When transcoding REST <-> gRPC or bridging gRPC-Web, the
//! proxy has to move an error between those two namespaces in both
//! directions. The tables below follow the mapping documented by the
//! gRPC project (`statuscodes.md`) and the Google API gateway
//! (`google.rpc.Code` <-> HTTP), which `grpc-gateway` and Envoy both
//! implement the same way.

/// A canonical gRPC status code (0 to 16).
///
/// `Ok` (0) means success; every other variant is an error. The numeric
/// value matches the integer carried in the `grpc-status` trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GrpcStatus {
    /// Not an error; returned on success.
    Ok = 0,
    /// The operation was cancelled, typically by the caller.
    Cancelled = 1,
    /// Unknown error.
    Unknown = 2,
    /// The client specified an invalid argument.
    InvalidArgument = 3,
    /// The deadline expired before the operation could complete.
    DeadlineExceeded = 4,
    /// Some requested entity was not found.
    NotFound = 5,
    /// The entity a client attempted to create already exists.
    AlreadyExists = 6,
    /// The caller does not have permission to execute the operation.
    PermissionDenied = 7,
    /// Some resource has been exhausted (quota, rate limit, disk).
    ResourceExhausted = 8,
    /// The operation was rejected because the system is not in a state
    /// required for the operation's execution.
    FailedPrecondition = 9,
    /// The operation was aborted, typically due to a concurrency issue.
    Aborted = 10,
    /// The operation was attempted past the valid range.
    OutOfRange = 11,
    /// The operation is not implemented or not supported.
    Unimplemented = 12,
    /// An internal error; an invariant expected by the system was broken.
    Internal = 13,
    /// The service is currently unavailable (transient).
    Unavailable = 14,
    /// Unrecoverable data loss or corruption.
    DataLoss = 15,
    /// The request does not have valid authentication credentials.
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// The integer carried in the `grpc-status` trailer.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Parse a `grpc-status` trailer integer into a [`GrpcStatus`].
    ///
    /// Out-of-range values fall back to [`GrpcStatus::Unknown`], which
    /// mirrors how a gRPC client treats a code it does not recognise.
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Cancelled,
            2 => Self::Unknown,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }

    /// The stable upper-snake-case name (for example `NOT_FOUND`),
    /// matching the `google.rpc.Code` enum names.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
            Self::Unauthenticated => "UNAUTHENTICATED",
        }
    }

    /// Map a gRPC status to the HTTP status used in a transcoded REST
    /// response. Follows the `google.rpc.Code` to HTTP mapping that
    /// `grpc-gateway` uses.
    pub fn to_http_status(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::Cancelled => 499,
            Self::Unknown => 500,
            Self::InvalidArgument => 400,
            Self::DeadlineExceeded => 504,
            Self::NotFound => 404,
            Self::AlreadyExists => 409,
            Self::PermissionDenied => 403,
            Self::ResourceExhausted => 429,
            Self::FailedPrecondition => 400,
            Self::Aborted => 409,
            Self::OutOfRange => 400,
            Self::Unimplemented => 501,
            Self::Internal => 500,
            Self::Unavailable => 503,
            Self::DataLoss => 500,
            Self::Unauthenticated => 401,
        }
    }

    /// Map an inbound HTTP status to the gRPC status the proxy should
    /// surface when an HTTP error occurs before the upstream returns a
    /// gRPC trailer (for example a 502 from a connect failure). This
    /// follows the gRPC project's `http-grpc-status-mapping.md`.
    pub fn from_http_status(http: u16) -> Self {
        match http {
            400 => Self::Internal,
            401 => Self::Unauthenticated,
            403 => Self::PermissionDenied,
            404 => Self::Unimplemented,
            429 => Self::Unavailable,
            502 => Self::Unavailable,
            503 => Self::Unavailable,
            504 => Self::Unavailable,
            s if (200..300).contains(&s) => Self::Ok,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_roundtrips_through_from_code() {
        for code in 0..=16 {
            let status = GrpcStatus::from_code(code);
            assert_eq!(status.code(), code, "code {code} should round-trip");
        }
    }

    #[test]
    fn unknown_code_falls_back_to_unknown() {
        assert_eq!(GrpcStatus::from_code(99), GrpcStatus::Unknown);
        assert_eq!(GrpcStatus::from_code(-1), GrpcStatus::Unknown);
    }

    #[test]
    fn grpc_to_http_mapping_matches_grpc_gateway() {
        assert_eq!(GrpcStatus::Ok.to_http_status(), 200);
        assert_eq!(GrpcStatus::InvalidArgument.to_http_status(), 400);
        assert_eq!(GrpcStatus::Unauthenticated.to_http_status(), 401);
        assert_eq!(GrpcStatus::PermissionDenied.to_http_status(), 403);
        assert_eq!(GrpcStatus::NotFound.to_http_status(), 404);
        assert_eq!(GrpcStatus::AlreadyExists.to_http_status(), 409);
        assert_eq!(GrpcStatus::ResourceExhausted.to_http_status(), 429);
        assert_eq!(GrpcStatus::Unimplemented.to_http_status(), 501);
        assert_eq!(GrpcStatus::Unavailable.to_http_status(), 503);
        assert_eq!(GrpcStatus::DeadlineExceeded.to_http_status(), 504);
        assert_eq!(GrpcStatus::Internal.to_http_status(), 500);
    }

    #[test]
    fn http_to_grpc_mapping_matches_spec() {
        assert_eq!(GrpcStatus::from_http_status(200), GrpcStatus::Ok);
        assert_eq!(GrpcStatus::from_http_status(204), GrpcStatus::Ok);
        assert_eq!(GrpcStatus::from_http_status(400), GrpcStatus::Internal);
        assert_eq!(
            GrpcStatus::from_http_status(401),
            GrpcStatus::Unauthenticated
        );
        assert_eq!(
            GrpcStatus::from_http_status(403),
            GrpcStatus::PermissionDenied
        );
        assert_eq!(GrpcStatus::from_http_status(404), GrpcStatus::Unimplemented);
        assert_eq!(GrpcStatus::from_http_status(502), GrpcStatus::Unavailable);
        assert_eq!(GrpcStatus::from_http_status(503), GrpcStatus::Unavailable);
        assert_eq!(GrpcStatus::from_http_status(504), GrpcStatus::Unavailable);
        assert_eq!(GrpcStatus::from_http_status(418), GrpcStatus::Unknown);
    }

    #[test]
    fn names_match_google_rpc_code() {
        assert_eq!(GrpcStatus::Ok.name(), "OK");
        assert_eq!(GrpcStatus::NotFound.name(), "NOT_FOUND");
        assert_eq!(GrpcStatus::InvalidArgument.name(), "INVALID_ARGUMENT");
        assert_eq!(GrpcStatus::Unauthenticated.name(), "UNAUTHENTICATED");
    }
}

//! Status and body rules every extension-produced response must satisfy.
//!
//! A bundle hook can hand the host a complete response instead of an
//! upstream: a dynamic action returns one, and a Proxy-Wasm filter sends
//! one through `proxy_send_local_response`. Both surfaces stop dispatch
//! and write the guest's bytes downstream, so both need the same answer
//! to two questions HTTP does not let the host defer.
//!
//! An informational (1xx) status is not a final response. A guest that
//! sends one is asking the host to keep going, but the host has already
//! torn dispatch down, so the client would be left waiting on a final
//! status that can never arrive. Rejecting it before any byte reaches
//! the wire is the only outcome that keeps the connection honest.
//!
//! A 204 or 304 carries no body by definition (RFC 9110 sections 15.3.5
//! and 15.4.5). Framing a body under one of those statuses desynchronizes
//! an HTTP/1 connection and is a protocol error on HTTP/2, so a guest
//! body there is rejected rather than silently dropped: silently dropping
//! it would make a bundle that believes it is returning content look like
//! it is working.
//!
//! Every message here is a fixed string plus, at most, the status the
//! guest chose. No guest-supplied bytes reach the error, so a hostile
//! bundle cannot use a rejection to smuggle content into host logs or
//! into an operator's terminal.

/// Why an extension-produced response cannot be written downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionResponseError {
    /// Status is outside the range HTTP defines.
    StatusOutOfRange {
        /// The status the guest supplied.
        status: u16,
    },
    /// Status is informational, so it cannot terminate dispatch.
    InformationalStatus {
        /// The status the guest supplied.
        status: u16,
    },
    /// Status forbids a body and the guest supplied one anyway.
    BodyForbidden {
        /// The status the guest supplied.
        status: u16,
    },
}

impl std::fmt::Display for ExtensionResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatusOutOfRange { status } => {
                write!(f, "extension response status must be in 100..=599, got {status}")
            }
            Self::InformationalStatus { status } => write!(
                f,
                "extension response status {status} is informational; a hook that ends dispatch must return a final status (200..=599)"
            ),
            Self::BodyForbidden { status } => write!(
                f,
                "extension response status {status} forbids a response body"
            ),
        }
    }
}

impl std::error::Error for ExtensionResponseError {}

/// Return whether HTTP forbids a response body for `status`.
///
/// 204 and 304 are the only final statuses that forbid one. 205 is not
/// included: it requires an empty body, which it is allowed to frame,
/// and rejecting it would fail a response that is well formed.
#[must_use]
pub const fn status_forbids_body(status: u16) -> bool {
    matches!(status, 204 | 304)
}

/// Check the status and body an extension hook produced.
///
/// Callers run this before writing any byte downstream, so a rejection
/// can still become a host error response rather than a truncated or
/// desynchronized stream.
pub fn validate_extension_response(
    status: u16,
    body_len: usize,
) -> Result<(), ExtensionResponseError> {
    if !(100..=599).contains(&status) {
        return Err(ExtensionResponseError::StatusOutOfRange { status });
    }
    if status < 200 {
        return Err(ExtensionResponseError::InformationalStatus { status });
    }
    if status_forbids_body(status) && body_len > 0 {
        return Err(ExtensionResponseError::BodyForbidden { status });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_final_statuses_pass_with_or_without_a_body() {
        for status in [200, 201, 400, 404, 500, 599] {
            assert!(validate_extension_response(status, 0).is_ok());
            assert!(validate_extension_response(status, 12).is_ok());
        }
    }

    #[test]
    fn informational_statuses_cannot_end_dispatch() {
        for status in [100, 101, 103, 199] {
            assert_eq!(
                validate_extension_response(status, 0),
                Err(ExtensionResponseError::InformationalStatus { status }),
            );
        }
    }

    #[test]
    fn bodyless_statuses_reject_a_body_and_accept_an_empty_one() {
        for status in [204, 304] {
            assert!(validate_extension_response(status, 0).is_ok());
            assert_eq!(
                validate_extension_response(status, 1),
                Err(ExtensionResponseError::BodyForbidden { status }),
            );
        }
    }

    #[test]
    fn a_205_may_frame_its_empty_body() {
        assert!(!status_forbids_body(205));
        assert!(validate_extension_response(205, 0).is_ok());
    }

    #[test]
    fn out_of_range_statuses_are_named_before_any_other_rule() {
        assert_eq!(
            validate_extension_response(99, 0),
            Err(ExtensionResponseError::StatusOutOfRange { status: 99 }),
        );
        assert_eq!(
            validate_extension_response(600, 4),
            Err(ExtensionResponseError::StatusOutOfRange { status: 600 }),
        );
    }

    #[test]
    fn no_message_can_carry_guest_supplied_bytes() {
        // The rejection reaches operator logs and, for the action
        // surface, a host error response. Every arm is a fixed string
        // plus the status, so a hostile bundle has no channel here.
        let rendered = [
            ExtensionResponseError::StatusOutOfRange { status: 600 }.to_string(),
            ExtensionResponseError::InformationalStatus { status: 100 }.to_string(),
            ExtensionResponseError::BodyForbidden { status: 204 }.to_string(),
        ];
        for message in rendered {
            assert!(message.starts_with("extension response status"));
        }
    }
}

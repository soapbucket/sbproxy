//! gRPC-Web <-> gRPC bridging.
//!
//! A browser gRPC-Web client cannot speak native gRPC: it runs over
//! HTTP/1.1 (or HTTP/2) and cannot read HTTP trailers, which is where
//! native gRPC carries `grpc-status` and `grpc-message`. gRPC-Web
//! therefore moves the trailers into the response *body* as a special
//! trailer frame: a length-prefixed frame whose flag byte has the most
//! significant bit set (`0x80`), carrying the trailers as an
//! HTTP/1.1-style `key: value\r\n` block.
//!
//! Two content types exist: `application/grpc-web+proto` carries raw
//! binary frames, while `application/grpc-web-text` base64-encodes the
//! whole stream so it survives text-only intermediaries. This module
//! bridges in both directions for unary and server-streaming calls:
//!
//! - [`GrpcWebBridge::decode_request`] takes a gRPC-Web request body and
//!   yields the native gRPC frames to forward upstream.
//! - [`GrpcWebBridge::encode_response`] takes the native gRPC response
//!   frames plus the trailers and yields the gRPC-Web response body
//!   (message frames followed by one trailer frame).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use super::frame::{self, FRAME_HEADER_LEN};
use super::status::GrpcStatus;

/// gRPC-Web trailer frame flag (the high bit of the flag byte).
const TRAILER_FLAG: u8 = 0x80;

/// Whether a `content-type` is any gRPC-Web variant.
pub fn is_grpc_web(content_type: &str) -> bool {
    content_type
        .trim()
        .to_ascii_lowercase()
        .starts_with("application/grpc-web")
}

/// Whether a gRPC-Web `content-type` is the base64 text variant.
pub fn is_text_encoded(content_type: &str) -> bool {
    content_type.to_ascii_lowercase().contains("grpc-web-text")
}

/// The native gRPC response trailers to fold into a gRPC-Web body.
#[derive(Debug, Clone)]
pub struct GrpcTrailers {
    /// The `grpc-status` integer.
    pub status: i32,
    /// The optional `grpc-message` text.
    pub message: Option<String>,
}

impl GrpcTrailers {
    /// A success trailer (`grpc-status: 0`).
    pub fn ok() -> Self {
        Self {
            status: GrpcStatus::Ok.code(),
            message: None,
        }
    }
}

/// Stateless gRPC-Web bridge.
pub struct GrpcWebBridge;

impl GrpcWebBridge {
    /// Decode a gRPC-Web request body into native gRPC message frames.
    ///
    /// When `text` is set the body is base64-decoded first. The returned
    /// bytes are one or more native gRPC length-prefixed frames suitable
    /// for forwarding to a native gRPC upstream verbatim.
    pub fn decode_request(body: &[u8], text: bool) -> anyhow::Result<Vec<u8>> {
        let raw = if text {
            decode_base64_lenient(body)?
        } else {
            body.to_vec()
        };
        // Validate framing so a malformed client request fails here
        // rather than confusing the upstream. Request bodies never carry
        // a trailer frame, so any trailer flag is rejected.
        let frames = frame::decode_all(&raw)?;
        if frames.is_empty() {
            anyhow::bail!("gRPC-Web request carried no message frame");
        }
        Ok(raw)
    }

    /// Encode native gRPC response frames plus trailers into a gRPC-Web
    /// response body.
    ///
    /// `message_frames` is the concatenation of zero or more native gRPC
    /// length-prefixed message frames (one for unary, many for
    /// server-streaming). The trailer frame is appended last. When
    /// `text` is set the whole body is base64-encoded.
    pub fn encode_response(message_frames: &[u8], trailers: &GrpcTrailers, text: bool) -> Vec<u8> {
        let mut body = message_frames.to_vec();
        body.extend_from_slice(&encode_trailer_frame(trailers));
        if text {
            BASE64.encode(&body).into_bytes()
        } else {
            body
        }
    }

    /// The `content-type` the bridge should set on the response, given
    /// the request's gRPC-Web content type.
    pub fn response_content_type(request_content_type: &str) -> &'static str {
        if is_text_encoded(request_content_type) {
            "application/grpc-web-text+proto"
        } else {
            "application/grpc-web+proto"
        }
    }
}

/// Build a gRPC-Web trailer frame from the native trailers.
///
/// The trailer payload is an HTTP/1.1-style block: lowercase header
/// names, `: ` separators, `\r\n` terminators. The frame header uses the
/// trailer flag byte (`0x80`).
fn encode_trailer_frame(trailers: &GrpcTrailers) -> Vec<u8> {
    let mut block = format!("grpc-status: {}\r\n", trailers.status);
    if let Some(msg) = &trailers.message {
        // Trailer values are percent-escaped per the gRPC spec; for the
        // common ASCII case a plain copy is correct, and any embedded
        // CR/LF would corrupt the block, so strip them defensively.
        let sanitized: String = msg.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        block.push_str(&format!("grpc-message: {sanitized}\r\n"));
    }
    let payload = block.into_bytes();
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.push(TRAILER_FLAG);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// Parse a gRPC-Web trailer frame's payload back into [`GrpcTrailers`].
///
/// Exposed for the reverse direction (a gRPC-Web upstream answering a
/// native gRPC client) and for tests. Returns `None` when the block has
/// no `grpc-status` line.
pub fn parse_trailer_block(payload: &[u8]) -> Option<GrpcTrailers> {
    let text = String::from_utf8_lossy(payload);
    let mut status = None;
    let mut message = None;
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "grpc-status" => status = val.parse::<i32>().ok(),
                "grpc-message" => message = Some(val.to_string()),
                _ => {}
            }
        }
    }
    status.map(|s| GrpcTrailers { status: s, message })
}

/// Lenient base64 decode that strips whitespace inserted by text
/// transports before decoding.
fn decode_base64_lenient(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(data)
        .map_err(|e| anyhow::anyhow!("invalid UTF-8 in base64 gRPC-Web frame: {e}"))?;
    let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64
        .decode(stripped.as_bytes())
        .map_err(|e| anyhow::anyhow!("base64 decode error in gRPC-Web frame: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_detection() {
        assert!(is_grpc_web("application/grpc-web"));
        assert!(is_grpc_web("application/grpc-web+proto"));
        assert!(is_grpc_web("application/grpc-web-text"));
        assert!(is_grpc_web("APPLICATION/GRPC-WEB-TEXT"));
        assert!(!is_grpc_web("application/grpc"));
        assert!(!is_grpc_web("application/json"));
    }

    #[test]
    fn text_encoding_detection() {
        assert!(is_text_encoded("application/grpc-web-text"));
        assert!(is_text_encoded("application/grpc-web-text+proto"));
        assert!(!is_text_encoded("application/grpc-web+proto"));
    }

    #[test]
    fn decode_binary_request_passthrough() {
        let inner = frame::encode_message(b"hello");
        let decoded = GrpcWebBridge::decode_request(&inner, false).unwrap();
        assert_eq!(decoded, inner);
    }

    #[test]
    fn decode_text_request_base64() {
        let inner = frame::encode_message(b"hello");
        let b64 = BASE64.encode(&inner).into_bytes();
        let decoded = GrpcWebBridge::decode_request(&b64, true).unwrap();
        assert_eq!(decoded, inner);
    }

    #[test]
    fn decode_empty_request_errors() {
        assert!(GrpcWebBridge::decode_request(&[], false).is_err());
    }

    #[test]
    fn encode_unary_response_appends_trailer() {
        let msg = frame::encode_message(b"response-body");
        let body = GrpcWebBridge::encode_response(&msg, &GrpcTrailers::ok(), false);
        // The first frame is the message; the last is the trailer frame.
        let frames = frame::decode_all_raw(&body);
        assert_eq!(frames.len(), 2);
        // Message frame flag is 0x00.
        assert_eq!(body[0], 0x00);
        // Trailer frame flag is 0x80.
        let trailer_start = msg.len();
        assert_eq!(body[trailer_start], TRAILER_FLAG);
    }

    #[test]
    fn encode_streaming_response_keeps_all_message_frames() {
        let mut msgs = frame::encode_message(b"chunk-1");
        msgs.extend(frame::encode_message(b"chunk-2"));
        msgs.extend(frame::encode_message(b"chunk-3"));
        let body = GrpcWebBridge::encode_response(&msgs, &GrpcTrailers::ok(), false);
        // 3 message frames + 1 trailer frame.
        let frames = frame::decode_all_raw(&body);
        assert_eq!(frames.len(), 4);
    }

    #[test]
    fn trailer_frame_roundtrips() {
        let trailers = GrpcTrailers {
            status: GrpcStatus::NotFound.code(),
            message: Some("not here".to_string()),
        };
        let body = GrpcWebBridge::encode_response(&[], &trailers, false);
        // The body is just the trailer frame; strip the header and parse.
        assert_eq!(body[0], TRAILER_FLAG);
        let payload = &body[FRAME_HEADER_LEN..];
        let parsed = parse_trailer_block(payload).unwrap();
        assert_eq!(parsed.status, GrpcStatus::NotFound.code());
        assert_eq!(parsed.message.as_deref(), Some("not here"));
    }

    #[test]
    fn text_response_is_base64() {
        let msg = frame::encode_message(b"x");
        let body = GrpcWebBridge::encode_response(&msg, &GrpcTrailers::ok(), true);
        // Decodes as base64 and the decoded bytes start with a message frame.
        let decoded = BASE64.decode(&body).unwrap();
        assert_eq!(decoded[0], 0x00);
    }

    #[test]
    fn response_content_type_tracks_request() {
        assert_eq!(
            GrpcWebBridge::response_content_type("application/grpc-web-text"),
            "application/grpc-web-text+proto"
        );
        assert_eq!(
            GrpcWebBridge::response_content_type("application/grpc-web+proto"),
            "application/grpc-web+proto"
        );
    }

    #[test]
    fn trailer_block_without_status_is_none() {
        assert!(parse_trailer_block(b"grpc-message: hi\r\n").is_none());
    }
}

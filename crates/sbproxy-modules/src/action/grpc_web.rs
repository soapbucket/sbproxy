//! gRPC-Web to gRPC transcoding.
//!
//! Translates gRPC-Web framing (base64/binary over HTTP/1.1) to native gRPC.
//!
//! gRPC-Web uses the same 5-byte length-prefix framing as standard gRPC, but
//! allows transport over plain HTTP/1.1 by encoding the frame in base64
//! (content-type: application/grpc-web-text) or raw binary
//! (content-type: application/grpc-web+proto or application/grpc-web).
//! This module detects, decodes, and re-encodes these frames for proxying.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

/// gRPC-Web frame flag byte: 0x00 = data frame, 0x80 = trailer frame.
const GRPC_WEB_DATA_FLAG: u8 = 0x00;
const GRPC_FRAME_HEADER_LEN: usize = 5;

/// gRPC-Web to gRPC transcoder.
///
/// Stateless helper that handles content-type detection and
/// frame encoding/decoding for gRPC-Web over HTTP/1.1.
pub struct GrpcWebTranscoder;

impl GrpcWebTranscoder {
    /// Check if a request is gRPC-Web based on its Content-Type header value.
    ///
    /// Matches `application/grpc-web`, `application/grpc-web+proto`, and
    /// `application/grpc-web-text` (and `+proto` variant of text).
    pub fn is_grpc_web(content_type: &str) -> bool {
        let ct = content_type.trim().to_lowercase();
        ct.starts_with("application/grpc-web")
    }

    /// Check if a gRPC-Web request uses base64 encoding.
    ///
    /// Returns `true` for `application/grpc-web-text` variants, which encode
    /// the binary frame in base64 for HTTP/1.1 compatibility with text-only
    /// proxies (e.g., older nginx without binary passthrough).
    pub fn is_base64_encoded(content_type: &str) -> bool {
        let ct = content_type.trim().to_lowercase();
        ct.contains("grpc-web-text")
    }

    /// Decode a gRPC-Web request frame.
    ///
    /// For binary frames (`is_base64 = false`): the input is already a 5-byte
    /// prefixed gRPC frame; return it as-is (strip leading padding if any).
    ///
    /// For base64 frames (`is_base64 = true`): base64-decode first, then
    /// validate the 5-byte gRPC framing prefix and return the payload bytes
    /// (including the 5-byte header so the upstream gRPC server can read it
    /// as a standard gRPC data frame).
    pub fn decode_frame(data: &[u8], is_base64: bool) -> anyhow::Result<Vec<u8>> {
        let raw = if is_base64 {
            // Strip whitespace that may have been added for HTTP text transport.
            let text = std::str::from_utf8(data)
                .map_err(|e| anyhow::anyhow!("invalid UTF-8 in base64 frame: {e}"))?;
            let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            BASE64
                .decode(stripped.as_bytes())
                .map_err(|e| anyhow::anyhow!("base64 decode error: {e}"))?
        } else {
            data.to_vec()
        };

        if raw.len() < GRPC_FRAME_HEADER_LEN {
            anyhow::bail!(
                "frame too short: {} bytes (minimum {})",
                raw.len(),
                GRPC_FRAME_HEADER_LEN
            );
        }

        Ok(raw)
    }

    /// Encode a gRPC response payload as a gRPC-Web frame.
    ///
    /// Prepends the 5-byte gRPC length-prefix header (flag byte 0x00 followed
    /// by 4-byte big-endian payload length), then optionally base64-encodes
    /// the result for text transport.
    pub fn encode_frame(data: &[u8], use_base64: bool) -> Vec<u8> {
        let payload_len = data.len() as u32;
        let mut frame = Vec::with_capacity(GRPC_FRAME_HEADER_LEN + data.len());

        // 5-byte gRPC framing header: [flag(1)] + [length(4, big-endian)].
        frame.push(GRPC_WEB_DATA_FLAG);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(data);

        if use_base64 {
            BASE64.encode(&frame).into_bytes()
        } else {
            frame
        }
    }

    /// Extract the payload bytes from an already-decoded gRPC frame.
    ///
    /// Reads the 5-byte header and returns a slice of the message payload.
    /// Returns an error if the frame is malformed or the declared length
    /// exceeds the available data.
    pub fn extract_payload(frame: &[u8]) -> anyhow::Result<&[u8]> {
        if frame.len() < GRPC_FRAME_HEADER_LEN {
            anyhow::bail!("frame too short for header");
        }
        let payload_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        let end = GRPC_FRAME_HEADER_LEN + payload_len;
        if frame.len() < end {
            anyhow::bail!(
                "frame payload length {} exceeds available data {}",
                payload_len,
                frame.len() - GRPC_FRAME_HEADER_LEN
            );
        }
        Ok(&frame[GRPC_FRAME_HEADER_LEN..end])
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_grpc_web tests ---

    #[test]
    fn detect_grpc_web_binary() {
        assert!(GrpcWebTranscoder::is_grpc_web("application/grpc-web"));
        assert!(GrpcWebTranscoder::is_grpc_web("application/grpc-web+proto"));
        assert!(GrpcWebTranscoder::is_grpc_web(
            "application/grpc-web; charset=utf-8"
        ));
    }

    #[test]
    fn detect_grpc_web_text() {
        assert!(GrpcWebTranscoder::is_grpc_web("application/grpc-web-text"));
        assert!(GrpcWebTranscoder::is_grpc_web(
            "application/grpc-web-text+proto"
        ));
    }

    #[test]
    fn detect_grpc_web_case_insensitive() {
        assert!(GrpcWebTranscoder::is_grpc_web("Application/GRPC-WEB"));
        assert!(GrpcWebTranscoder::is_grpc_web("APPLICATION/GRPC-WEB-TEXT"));
    }

    #[test]
    fn non_grpc_web_content_types_rejected() {
        assert!(!GrpcWebTranscoder::is_grpc_web("application/grpc"));
        assert!(!GrpcWebTranscoder::is_grpc_web("application/json"));
        assert!(!GrpcWebTranscoder::is_grpc_web("text/plain"));
        assert!(!GrpcWebTranscoder::is_grpc_web(""));
    }

    #[test]
    fn is_base64_encoded_text_variants() {
        assert!(GrpcWebTranscoder::is_base64_encoded(
            "application/grpc-web-text"
        ));
        assert!(GrpcWebTranscoder::is_base64_encoded(
            "application/grpc-web-text+proto"
        ));
    }

    #[test]
    fn is_base64_encoded_binary_variants() {
        assert!(!GrpcWebTranscoder::is_base64_encoded(
            "application/grpc-web"
        ));
        assert!(!GrpcWebTranscoder::is_base64_encoded(
            "application/grpc-web+proto"
        ));
    }

    // --- encode_frame tests ---

    #[test]
    fn encode_frame_binary() {
        let payload = b"hello, grpc";
        let frame = GrpcWebTranscoder::encode_frame(payload, false);

        // Flag byte = 0x00.
        assert_eq!(frame[0], 0x00);
        // Length bytes (big-endian u32).
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        assert_eq!(len as usize, payload.len());
        // Payload follows.
        assert_eq!(&frame[5..], payload);
    }

    #[test]
    fn encode_frame_base64() {
        let payload = b"test payload";
        let frame = GrpcWebTranscoder::encode_frame(payload, true);

        // Should be valid base64.
        let decoded = BASE64.decode(&frame).expect("should be valid base64");
        assert_eq!(decoded[0], 0x00);
        let len = u32::from_be_bytes([decoded[1], decoded[2], decoded[3], decoded[4]]);
        assert_eq!(len as usize, payload.len());
        assert_eq!(&decoded[5..], payload);
    }

    // --- decode_frame tests ---

    #[test]
    fn decode_frame_binary_passthrough() {
        let payload = b"grpc payload here";
        // Build a valid 5-byte prefixed frame.
        let mut frame = vec![0x00u8];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);

        let decoded = GrpcWebTranscoder::decode_frame(&frame, false).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_frame_base64_roundtrip() {
        let payload = b"roundtrip test data";
        // Encode as gRPC-Web text frame.
        let encoded = GrpcWebTranscoder::encode_frame(payload, true);
        // Decode back.
        let decoded = GrpcWebTranscoder::decode_frame(&encoded, true).unwrap();

        // The decoded frame includes the 5-byte header.
        assert_eq!(decoded[0], 0x00);
        let len = u32::from_be_bytes([decoded[1], decoded[2], decoded[3], decoded[4]]);
        assert_eq!(len as usize, payload.len());
        assert_eq!(&decoded[5..], payload);
    }

    #[test]
    fn decode_frame_too_short_errors() {
        let short = b"\x00\x00";
        let result = GrpcWebTranscoder::decode_frame(short, false);
        assert!(result.is_err());
    }

    #[test]
    fn decode_frame_invalid_base64_errors() {
        let bad_b64 = b"!!!not-valid-base64!!!";
        let result = GrpcWebTranscoder::decode_frame(bad_b64, true);
        assert!(result.is_err());
    }

    // --- extract_payload tests ---

    #[test]
    fn extract_payload_correct() {
        let payload = b"extracted data";
        let frame = GrpcWebTranscoder::encode_frame(payload, false);
        let extracted = GrpcWebTranscoder::extract_payload(&frame).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn extract_payload_empty_payload() {
        let frame = GrpcWebTranscoder::encode_frame(b"", false);
        let extracted = GrpcWebTranscoder::extract_payload(&frame).unwrap();
        assert_eq!(extracted, b"");
    }

    #[test]
    fn extract_payload_short_frame_errors() {
        let result = GrpcWebTranscoder::extract_payload(b"\x00\x00");
        assert!(result.is_err());
    }

    // --- encode/decode roundtrip tests ---

    #[test]
    fn encode_decode_roundtrip_binary() {
        let original = b"some grpc message payload with unicode: \xc3\xa9";
        let encoded = GrpcWebTranscoder::encode_frame(original, false);
        let decoded = GrpcWebTranscoder::decode_frame(&encoded, false).unwrap();
        let payload = GrpcWebTranscoder::extract_payload(&decoded).unwrap();
        assert_eq!(payload, original);
    }

    #[test]
    fn encode_decode_roundtrip_base64() {
        let original = b"another message for the roundtrip test";
        let encoded = GrpcWebTranscoder::encode_frame(original, true);
        let decoded = GrpcWebTranscoder::decode_frame(&encoded, true).unwrap();
        let payload = GrpcWebTranscoder::extract_payload(&decoded).unwrap();
        assert_eq!(payload, original);
    }
}

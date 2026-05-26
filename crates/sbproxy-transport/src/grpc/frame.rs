//! gRPC length-prefixed message framing.
//!
//! Every gRPC message on the wire is a 5-byte header followed by the
//! serialized protobuf payload. The header is one compression flag byte
//! (`0x00` uncompressed, `0x01` compressed) and a 4-byte big-endian
//! length. This module builds and parses that framing; it is shared by
//! the REST <-> gRPC transcoder and the gRPC-Web bridge so both produce
//! and consume byte-identical frames.

/// Length of the gRPC message header in bytes (1 flag + 4 length).
pub const FRAME_HEADER_LEN: usize = 5;

/// Compression flag for an uncompressed gRPC frame.
pub const FLAG_UNCOMPRESSED: u8 = 0x00;

/// Compression flag for a compressed gRPC frame.
pub const FLAG_COMPRESSED: u8 = 0x01;

/// Wrap a serialized protobuf payload in a single uncompressed gRPC
/// length-prefixed frame.
pub fn encode_message(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.push(FLAG_UNCOMPRESSED);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// A single parsed gRPC frame: its compression flag and payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// True when the compression flag byte was set (`0x01`).
    pub compressed: bool,
    /// The message payload (the protobuf bytes), without the 5-byte
    /// header.
    pub payload: Vec<u8>,
}

/// Decode the first gRPC frame from `data`.
///
/// Returns the parsed frame and the number of bytes consumed (header +
/// payload), so a caller can iterate over a buffer that holds more than
/// one frame. Errors when the buffer is shorter than the header or the
/// declared payload length runs past the available bytes.
pub fn decode_one(data: &[u8]) -> anyhow::Result<(Frame, usize)> {
    if data.len() < FRAME_HEADER_LEN {
        anyhow::bail!(
            "gRPC frame too short: {} bytes (need at least {})",
            data.len(),
            FRAME_HEADER_LEN
        );
    }
    let compressed = match data[0] {
        FLAG_UNCOMPRESSED => false,
        FLAG_COMPRESSED => true,
        other => anyhow::bail!("invalid gRPC frame flag byte: 0x{other:02x}"),
    };
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let end = FRAME_HEADER_LEN + len;
    if data.len() < end {
        anyhow::bail!(
            "gRPC frame payload length {} exceeds available data {}",
            len,
            data.len() - FRAME_HEADER_LEN
        );
    }
    Ok((
        Frame {
            compressed,
            payload: data[FRAME_HEADER_LEN..end].to_vec(),
        },
        end,
    ))
}

/// Decode every complete frame in `data`.
///
/// Used for server-streaming responses, where the body is a sequence of
/// length-prefixed frames. Trailing bytes that do not form a complete
/// frame are an error rather than being silently dropped.
pub fn decode_all(data: &[u8]) -> anyhow::Result<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (frame, consumed) = decode_one(&data[offset..])?;
        frames.push(frame);
        offset += consumed;
    }
    Ok(frames)
}

/// Split `data` into the byte ranges of each length-prefixed frame
/// without interpreting the flag byte.
///
/// Unlike [`decode_all`] this tolerates the gRPC-Web trailer flag
/// (`0x80`), so it can walk a complete gRPC-Web response body (message
/// frames followed by a trailer frame). Each returned slice is one full
/// frame including its 5-byte header. Trailing bytes that do not form a
/// complete frame are dropped.
pub fn decode_all_raw(data: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset + FRAME_HEADER_LEN <= data.len() {
        let len = u32::from_be_bytes([
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
        ]) as usize;
        let end = offset + FRAME_HEADER_LEN + len;
        if end > data.len() {
            break;
        }
        frames.push(&data[offset..end]);
        offset = end;
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode_roundtrips() {
        let payload = b"\x0a\x0bhello world";
        let frame = encode_message(payload);
        assert_eq!(frame[0], FLAG_UNCOMPRESSED);
        let (decoded, consumed) = decode_one(&frame).unwrap();
        assert!(!decoded.compressed);
        assert_eq!(decoded.payload, payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn encode_empty_payload() {
        let frame = encode_message(b"");
        assert_eq!(frame.len(), FRAME_HEADER_LEN);
        let (decoded, consumed) = decode_one(&frame).unwrap();
        assert!(decoded.payload.is_empty());
        assert_eq!(consumed, FRAME_HEADER_LEN);
    }

    #[test]
    fn decode_short_buffer_errors() {
        assert!(decode_one(b"\x00\x00").is_err());
    }

    #[test]
    fn decode_truncated_payload_errors() {
        // Header claims 10 bytes but only 2 follow.
        let mut buf = vec![FLAG_UNCOMPRESSED];
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(b"ab");
        assert!(decode_one(&buf).is_err());
    }

    #[test]
    fn decode_invalid_flag_errors() {
        let mut buf = vec![0x7f];
        buf.extend_from_slice(&0u32.to_be_bytes());
        assert!(decode_one(&buf).is_err());
    }

    #[test]
    fn decode_all_reads_multiple_frames() {
        let mut buf = encode_message(b"first");
        buf.extend(encode_message(b"second"));
        buf.extend(encode_message(b"third"));
        let frames = decode_all(&buf).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].payload, b"first");
        assert_eq!(frames[1].payload, b"second");
        assert_eq!(frames[2].payload, b"third");
    }

    #[test]
    fn decode_all_rejects_trailing_garbage() {
        let mut buf = encode_message(b"ok");
        buf.extend_from_slice(b"\x00\x00"); // incomplete second header
        assert!(decode_all(&buf).is_err());
    }
}

//! Binary wire encoding for mesh RPC frames and gossip messages.
//!
//! Centralizes the `bincode` serde bridge so every call site shares one
//! configuration. Uses bincode 2's `standard()` config (the maintained line;
//! bincode 1.x is unmaintained). The format is internal to a cluster: all nodes
//! agree on it, and there is no on-disk persistence in this format, so the
//! encoding is free to change with a coordinated mesh-protocol version bump.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Encode `value` to bincode bytes.
pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("bincode encode: {e}"))
}

/// Decode a `T` from bincode bytes (trailing bytes are ignored).
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    let (value, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("bincode decode: {e}"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_value() {
        let v: Vec<(String, u64)> = vec![("a".into(), 1), ("b".into(), 2)];
        let bytes = encode(&v).unwrap();
        let back: Vec<(String, u64)> = decode(&bytes).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode::<Vec<(String, u64)>>(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }
}

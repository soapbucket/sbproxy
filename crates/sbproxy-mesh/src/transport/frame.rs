//! Length-prefixed postcard framing for the cross-node cache RPC transport.
//!
//! Each wire frame is `[u32 big-endian length][postcard payload]`. The payload
//! is a [`Request`] on the wire from client to server, and a [`Response`] on
//! the wire from server back to client. Requests carry a monotonic
//! `request_id` so a single TCP connection could pipeline multiple in-flight
//! operations; the J2 MVP uses a serial request/response model per connection
//! and keeps this identifier for forward compatibility.
//!
//! Frame sizes are capped at 16 MiB to guard against malicious or buggy peers
//! claiming enormous lengths. Semantic-cache payloads are typically well
//! under 100 KiB, so the cap has headroom for ~100x growth before it bites.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Maximum permitted frame payload size, in bytes. Frames larger than this
/// are rejected on the read path to bound memory usage from a hostile peer.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

// --- Request / Response wire types ---

/// Outbound cache operation from the client half of the RPC.
///
/// `request_id` is monotonic per-connection (the client increments it for
/// every `send_request` call). The server echoes it back in the matching
/// [`Response`] so callers can correlate if a pipelined implementation is
/// wired later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Monotonic per-connection id. Echoed in the response.
    pub request_id: u64,
    /// The concrete cache operation to perform.
    pub op: CacheOp,
}

/// Cache operation variants carried inside [`Request`].
///
/// # Wire-format note (K1, K2)
///
/// `Put` carries a `ttl_secs` field as of K1. `ttl_secs = 0` means "no
/// expiry" (previous semantics); any positive value is interpreted by the
/// server as the number of seconds until the stored entry expires.
///
/// `PurgePrefix` was added in K2 to drive cluster-wide prefix / origin /
/// all purges. The server scans its local shard, deletes every matching
/// key, and replies with `CacheResult::Purged(n)`. An empty `prefix` means
/// "purge every entry" and is how the caller expresses a `PurgeScope::All`.
///
/// postcard does **not** honor `#[serde(default)]` on enum variants, so
/// every additive change to `CacheOp` is a wire-format break relative to
/// older nodes. All nodes in a cluster must upgrade together. New variants
/// are appended to the end so the discriminant ordering of older variants
/// does not shift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheOp {
    /// Fetch the value associated with `key`, if any.
    Get { key: String },
    /// Store `value` under `key`, overwriting any prior value. `ttl_secs`
    /// bounds the entry's lifetime on the owning node; `0` means no expiry.
    Put {
        key: String,
        value: Bytes,
        ttl_secs: u64,
    },
    /// Remove `key` from the cache; no-op if the key is absent.
    Delete { key: String },
    /// Delete every local entry whose key starts with `prefix`. An empty
    /// `prefix` means "purge every entry" (used to implement
    /// `PurgeScope::All`). The server replies with
    /// [`CacheResult::Purged`] carrying the number of entries removed on
    /// its local shard.
    PurgePrefix { prefix: String },
}

/// Server reply to a [`Request`]. Carries the original `request_id` so the
/// client can match responses to the originating send when pipelined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Echoed from the request.
    pub request_id: u64,
    /// The result payload for this request.
    pub result: CacheResult,
}

/// Result payload returned on a [`Response`]. `Value` is specific to `Get`;
/// `Acked` covers `Put`/`Delete`; `Purged(n)` covers `PurgePrefix`;
/// `Error` is used for internal failures that the server wants to surface
/// without tearing down the connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheResult {
    /// Reply to a `Get`: `Some(value)` on hit, `None` on miss.
    Value(Option<Bytes>),
    /// Reply to `Put` / `Delete`: operation accepted.
    Acked,
    /// Internal failure on the server. The string is advisory; callers should
    /// treat any `Error` as a transport-level failure and fall back to
    /// whatever their fail-open policy dictates (e.g. semantic cache miss).
    Error(String),
    /// Reply to `PurgePrefix`: count of entries removed on the server's
    /// local shard. Added in K2 as part of the cluster-wide purge fan-out.
    Purged(u64),
}

// --- Framing helpers ---

/// Write a framed payload to `w`. Frame layout is `[u32 BE length][payload]`.
///
/// Returns the number of payload bytes written on success (matches
/// `payload.len()`).
pub async fn write_frame<W>(w: &mut W, payload: &[u8]) -> tokio::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // Reject oversized frames on write as well so a buggy caller does not
    // blow past the receive-side cap and wedge the peer into a disconnect
    // loop.
    if payload.len() > MAX_FRAME_BYTES {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "frame payload exceeds 16 MiB cap",
        ));
    }
    let len = payload.len() as u32;
    w.write_u32(len).await?;
    w.write_all(payload).await?;
    Ok(())
}

/// Read a framed payload from `r`. Mirrors [`write_frame`].
///
/// Returns the raw payload bytes (the `u32` length prefix is consumed but
/// not included). Errors if the length prefix claims more than
/// [`MAX_FRAME_BYTES`] bytes, guarding against hostile peers.
pub async fn read_frame<R>(r: &mut R) -> tokio::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = r.read_u32().await? as usize;
    if len > MAX_FRAME_BYTES {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "frame exceeds 16 MiB cap",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn write_then_read_roundtrip_small() {
        let (mut a, mut b) = duplex(1024);
        let payload = b"hello-world";
        write_frame(&mut a, payload).await.expect("write");
        let read_back = read_frame(&mut b).await.expect("read");
        assert_eq!(read_back, payload);
    }

    #[tokio::test]
    async fn write_then_read_roundtrip_empty() {
        let (mut a, mut b) = duplex(64);
        write_frame(&mut a, &[]).await.expect("write");
        let read_back = read_frame(&mut b).await.expect("read");
        assert!(read_back.is_empty());
    }

    #[tokio::test]
    async fn request_wire_roundtrip_get() {
        let req = Request {
            request_id: 7,
            op: CacheOp::Get {
                key: "semcache:v1:k".to_string(),
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("serialize");
        let back: Request = crate::transport::wire::decode(&bytes).expect("deserialize");
        assert_eq!(back.request_id, 7);
        match back.op {
            CacheOp::Get { key } => assert_eq!(key, "semcache:v1:k"),
            other => panic!("expected Get, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn request_wire_roundtrip_put() {
        let req = Request {
            request_id: 99,
            op: CacheOp::Put {
                key: "k".to_string(),
                value: Bytes::from_static(b"payload-bytes"),
                ttl_secs: 0,
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("serialize");
        let back: Request = crate::transport::wire::decode(&bytes).expect("deserialize");
        assert_eq!(back.request_id, 99);
        match back.op {
            CacheOp::Put {
                key,
                value,
                ttl_secs,
            } => {
                assert_eq!(key, "k");
                assert_eq!(value, Bytes::from_static(b"payload-bytes"));
                assert_eq!(ttl_secs, 0);
            }
            other => panic!("expected Put, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn request_wire_roundtrip_put_with_ttl() {
        let req = Request {
            request_id: 100,
            op: CacheOp::Put {
                key: "k".to_string(),
                value: Bytes::from_static(b"v"),
                ttl_secs: 60,
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("serialize");
        let back: Request = crate::transport::wire::decode(&bytes).expect("deserialize");
        match back.op {
            CacheOp::Put { ttl_secs, .. } => assert_eq!(ttl_secs, 60),
            other => panic!("expected Put, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn response_wire_roundtrip_value() {
        let resp = Response {
            request_id: 1,
            result: CacheResult::Value(Some(Bytes::from_static(b"hit"))),
        };
        let bytes = crate::transport::wire::encode(&resp).expect("serialize");
        let back: Response = crate::transport::wire::decode(&bytes).expect("deserialize");
        assert_eq!(back.request_id, 1);
        match back.result {
            CacheResult::Value(Some(b)) => assert_eq!(b, Bytes::from_static(b"hit")),
            other => panic!("expected Value(Some), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn request_wire_roundtrip_purge_prefix() {
        // K2: PurgePrefix carries the scan prefix end-to-end. An empty
        // prefix is the "purge all" sentinel, which round-trips the same
        // way so we explicitly cover both cases.
        let req = Request {
            request_id: 42,
            op: CacheOp::PurgePrefix {
                prefix: "semcache:v1:foo:".to_string(),
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("serialize");
        let back: Request = crate::transport::wire::decode(&bytes).expect("deserialize");
        match back.op {
            CacheOp::PurgePrefix { prefix } => assert_eq!(prefix, "semcache:v1:foo:"),
            other => panic!("expected PurgePrefix, got {:?}", other),
        }

        let req_all = Request {
            request_id: 43,
            op: CacheOp::PurgePrefix {
                prefix: String::new(),
            },
        };
        let bytes = crate::transport::wire::encode(&req_all).expect("serialize");
        let back: Request = crate::transport::wire::decode(&bytes).expect("deserialize");
        match back.op {
            CacheOp::PurgePrefix { prefix } => assert!(prefix.is_empty()),
            other => panic!("expected PurgePrefix, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn response_wire_roundtrip_purged() {
        let resp = Response {
            request_id: 7,
            result: CacheResult::Purged(17),
        };
        let bytes = crate::transport::wire::encode(&resp).expect("serialize");
        let back: Response = crate::transport::wire::decode(&bytes).expect("deserialize");
        match back.result {
            CacheResult::Purged(n) => assert_eq!(n, 17),
            other => panic!("expected Purged, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn response_wire_roundtrip_acked() {
        let resp = Response {
            request_id: 1,
            result: CacheResult::Acked,
        };
        let bytes = crate::transport::wire::encode(&resp).expect("serialize");
        let back: Response = crate::transport::wire::decode(&bytes).expect("deserialize");
        match back.result {
            CacheResult::Acked => {}
            other => panic!("expected Acked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn write_frame_rejects_oversized_payload() {
        let (mut a, _b) = duplex(64);
        // Synthesise an oversized payload lazily: we only need a buffer
        // slightly over the cap. `Vec::new()` + claim by length is not
        // possible here, so allocate the cap+1 worth of zero bytes.
        let big = vec![0u8; MAX_FRAME_BYTES + 1];
        let err = write_frame(&mut a, &big).await.unwrap_err();
        assert_eq!(err.kind(), tokio::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_length_prefix() {
        // Construct a raw length prefix claiming MAX_FRAME_BYTES + 1 bytes.
        let (mut a, mut b) = duplex(64);
        use tokio::io::AsyncWriteExt;
        let claimed_len = (MAX_FRAME_BYTES as u32).saturating_add(1);
        a.write_u32(claimed_len).await.expect("write prefix");
        // Don't bother writing the body; `read_frame` should short-circuit on
        // the length check before attempting `read_exact`.
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), tokio::io::ErrorKind::InvalidData);
    }
}

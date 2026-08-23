//! Size-bounded reads for untrusted HTTP response bodies.

use anyhow::{anyhow, bail, Result};
use bytes::{Bytes, BytesMut};

/// Read at most `maximum` bytes from a remote response.
///
/// The limit is enforced while chunks arrive, rather than after
/// `Response::bytes` has allocated the complete peer-controlled body.
/// Errors intentionally contain no response bytes or transport detail,
/// because DCR/CIMD responses can carry credentials and hostile newlines.
pub(crate) async fn bounded_response_body(
    mut response: reqwest::Response,
    maximum: usize,
    label: &'static str,
) -> Result<Bytes> {
    if maximum == 0 {
        bail!("{label} response body limit is zero");
    }
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        bail!("{label} response body exceeds {maximum} byte limit");
    }

    let mut body = BytesMut::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("{label} response body read failed"))?
    {
        if body.len().saturating_add(chunk.len()) > maximum {
            bail!("{label} response body exceeds {maximum} byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

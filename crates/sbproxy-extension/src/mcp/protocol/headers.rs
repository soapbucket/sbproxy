//! Safe encoding and decoding for MCP routing-header values.

/// Error returned when an MCP routing-header value cannot be decoded safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeaderValueError {
    /// The Base64 sentinel does not contain valid Base64.
    #[error("invalid MCP Base64 header sentinel")]
    InvalidSentinel,
    /// The decoded Base64 sentinel is not valid UTF-8.
    #[error("MCP Base64 header sentinel is not UTF-8")]
    InvalidUtf8,
    /// The plain value is unsafe for an MCP routing header.
    #[error("unsafe plain MCP header value")]
    UnsafePlainValue,
}

/// Encode an MCP routing-header value, using a Base64 sentinel when needed.
pub fn encode_header_value(value: &str) -> String {
    use base64::Engine as _;

    let plain = !value.is_empty()
        && value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, 0x20..=0x7e | b'\t'))
        && value.trim() == value
        && !(value.starts_with("=?base64?") && value.ends_with("?="));
    if plain {
        value.to_string()
    } else {
        format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
        )
    }
}

/// Decode an MCP routing-header value, rejecting unsafe plain values.
pub fn decode_header_value(value: &str) -> Result<String, HeaderValueError> {
    use base64::Engine as _;

    if let Some(payload) = value
        .strip_prefix("=?base64?")
        .and_then(|rest| rest.strip_suffix("?="))
    {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| HeaderValueError::InvalidSentinel)?;
        return String::from_utf8(bytes).map_err(|_| HeaderValueError::InvalidUtf8);
    }
    if value.is_empty()
        || value.trim() != value
        || !value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, 0x20..=0x7e | b'\t'))
    {
        return Err(HeaderValueError::UnsafePlainValue);
    }
    Ok(value.to_string())
}

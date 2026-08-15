//! Strict MCP 2026-07-28 ingress codec.

use super::{
    decode_header_value, DecodedMcpRequest, DecodedRequestId, McpImplementation, McpProtocolCodec,
    McpProtocolContext, McpProtocolEra, McpRoutingHeaders, McpServerDescription, McpWireError,
    McpWireResponse,
};
use crate::mcp::types::{
    JsonRpcRequest, JsonRpcResponse, ModernJsonRpcResponse, ModernRequestId, HEADER_MISMATCH,
    META_CLIENT_CAPABILITIES, META_CLIENT_INFO, META_PROTOCOL_VERSION, META_SERVER_INFO,
    MISSING_REQUIRED_CLIENT_CAPABILITY, MODERN_PROTOCOL_VERSION, UNSUPPORTED_PROTOCOL_VERSION,
};

const PROTECTED_HEADERS: &[&str] = &[
    "content-type",
    "mcp-protocol-version",
    "mcp-method",
    "mcp-name",
];

fn implementation_value(implementation: &McpImplementation) -> serde_json::Value {
    serde_json::json!({
        "name": implementation.name,
        "version": implementation.version,
    })
}

/// Codec for strict MCP 2026-07-28 request ingress.
#[derive(Debug, Clone, Copy, Default)]
pub struct Modern2026_07_28Codec;

/// Build the modern capability object from the core surfaces the gateway serves.
pub fn modern_server_capabilities(
    has_tools: bool,
    has_resources: bool,
    has_prompts: bool,
) -> serde_json::Value {
    let mut capabilities = serde_json::Map::new();
    if has_tools {
        capabilities.insert("tools".into(), serde_json::json!({"listChanged": false}));
    }
    if has_resources {
        capabilities.insert(
            "resources".into(),
            serde_json::json!({"listChanged": false}),
        );
    }
    if has_prompts {
        capabilities.insert("prompts".into(), serde_json::json!({"listChanged": false}));
    }
    serde_json::Value::Object(capabilities)
}

/// Build a private, zero-TTL modern server discovery result.
pub fn build_discover_result(server: &McpServerDescription) -> serde_json::Value {
    let capabilities = modern_server_capabilities(
        server.capabilities.get("tools").is_some(),
        server.capabilities.get("resources").is_some(),
        server.capabilities.get("prompts").is_some(),
    );
    let mut meta = serde_json::Map::new();
    meta.insert(
        META_SERVER_INFO.into(),
        implementation_value(&server.implementation),
    );
    let mut result = serde_json::json!({
        "resultType": "complete",
        "supportedVersions": [
            MODERN_PROTOCOL_VERSION,
            crate::mcp::types::LEGACY_PROTOCOL_VERSION,
        ],
        "capabilities": capabilities,
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": meta,
    });
    if let Some(instructions) = &server.instructions {
        result["instructions"] = serde_json::Value::String(instructions.clone());
    }
    result
}

/// Return whether a response carries a recognized modern protocol error.
pub fn is_recognized_modern_error(response: &JsonRpcResponse) -> bool {
    response
        .error
        .as_ref()
        // -32020, -32021, and -32022: the contiguous modern protocol error block.
        .is_some_and(|error| matches!(error.code, -32022..=-32020))
}

impl Modern2026_07_28Codec {
    /// Decode an already scanned request with its lossless modern identifier.
    pub(super) fn decode_http_with_id(
        &self,
        request: JsonRpcRequest,
        request_id: ModernRequestId,
        headers: &http::HeaderMap,
    ) -> Result<DecodedMcpRequest, McpWireError> {
        validate_content_type(headers, request_id.clone())?;
        validate_accept(headers, request_id.clone())?;
        validate_no_duplicate_routing_headers(headers, request_id.clone())?;

        let metadata = request
            .params
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|params| params.get("_meta"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| invalid_params(request_id.clone(), "missing modern MCP metadata"))?;
        let body_version = metadata
            .get(META_PROTOCOL_VERSION)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                invalid_params(
                    request_id.clone(),
                    "missing modern MCP protocol version metadata",
                )
            })?;
        let capabilities = metadata
            .get(META_CLIENT_CAPABILITIES)
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| {
                invalid_params(request_id.clone(), "missing modern MCP client capabilities")
            })?;
        let client_info = metadata
            .get(META_CLIENT_INFO)
            .map(|value| serde_json::from_value::<McpImplementation>(value.clone()))
            .transpose()
            .map_err(|_| invalid_params(request_id.clone(), "invalid modern MCP client info"))?;

        let protocol_header = match headers.get("mcp-protocol-version") {
            None => {
                return Err(header_mismatch(
                    request_id.clone(),
                    "missing required MCP routing header",
                ));
            }
            Some(value) => match value.to_str() {
                Ok(value) if !value.is_empty() => value,
                _ => {
                    return Err(unsupported_version(request_id.clone(), None));
                }
            },
        };
        if protocol_header != body_version {
            return Err(header_mismatch(
                request_id.clone(),
                "MCP-Protocol-Version does not match body metadata",
            ));
        }
        if body_version != MODERN_PROTOCOL_VERSION {
            return Err(unsupported_version(request_id.clone(), Some(body_version)));
        }

        let method_header = required_header(headers, "mcp-method", request_id.clone())?;
        if method_header != request.method {
            return Err(header_mismatch(
                request_id.clone(),
                "Mcp-Method does not match JSON-RPC method",
            ));
        }
        let selector_key = match request.method.as_str() {
            "tools/call" | "prompts/get" => Some("name"),
            "resources/read" => Some("uri"),
            _ => None,
        };
        let decoded_name = if let Some(selector_key) = selector_key {
            let name = required_header(headers, "mcp-name", request_id.clone())?;
            let decoded_name = decode_header_value(name).map_err(|_| {
                header_mismatch(request_id.clone(), "invalid Mcp-Name header value")
            })?;
            let body_selector = request
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .and_then(|params| params.get(selector_key))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    header_mismatch(request_id.clone(), "missing or invalid MCP body selector")
                })?;
            if decoded_name != body_selector {
                return Err(header_mismatch(
                    request_id.clone(),
                    "Mcp-Name does not match the JSON-RPC body selector",
                ));
            }
            Some(decoded_name)
        } else {
            None
        };

        Ok(DecodedMcpRequest {
            request,
            request_id: DecodedRequestId::Modern(request_id),
            context: McpProtocolContext {
                era: McpProtocolEra::Modern2026_07_28,
                protocol_version: MODERN_PROTOCOL_VERSION.to_string(),
                client_capabilities: capabilities,
                client_info,
            },
            routing_headers: McpRoutingHeaders {
                method: Some(method_header.to_string()),
                name: decoded_name,
                params: mirrored_params(headers),
            },
        })
    }
}

impl McpProtocolCodec for Modern2026_07_28Codec {
    type RequestId = ModernRequestId;

    fn era(&self) -> McpProtocolEra {
        McpProtocolEra::Modern2026_07_28
    }

    fn decode_http(
        &self,
        _request: JsonRpcRequest,
        _headers: &http::HeaderMap,
    ) -> Result<DecodedMcpRequest, McpWireError> {
        Err(McpWireError::modern_json(
            http::StatusCode::BAD_REQUEST,
            ModernRequestId::Absent,
            crate::mcp::types::INVALID_REQUEST,
            "modern MCP decoding requires the raw envelope preflight",
            None,
        ))
    }

    fn encode_success(
        &self,
        method: &str,
        id: ModernRequestId,
        result: serde_json::Value,
        server: &McpServerDescription,
    ) -> Result<McpWireResponse, McpWireError> {
        if id.is_absent() {
            return Ok(McpWireResponse {
                status: http::StatusCode::ACCEPTED,
                headers: http::HeaderMap::new(),
                body: None,
            });
        }

        let mut result = result.as_object().cloned().ok_or_else(|| {
            internal_error(id.clone(), "modern MCP success result must be an object")
        })?;
        match result.entry("resultType") {
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(serde_json::Value::String("complete".into()));
            }
            serde_json::map::Entry::Occupied(entry)
                if entry.get() == &serde_json::Value::String("complete".into()) => {}
            serde_json::map::Entry::Occupied(_) => {
                return Err(internal_error(
                    id,
                    "modern MCP input-required results are not supported",
                ));
            }
        }

        let meta = match result.entry("_meta") {
            serde_json::map::Entry::Vacant(entry) => {
                match entry.insert(serde_json::Value::Object(serde_json::Map::new())) {
                    serde_json::Value::Object(meta) => meta,
                    _ => {
                        return Err(internal_error(
                            id,
                            "modern MCP result _meta must be an object",
                        ));
                    }
                }
            }
            serde_json::map::Entry::Occupied(entry) => match entry.into_mut() {
                serde_json::Value::Object(meta) => meta,
                _ => {
                    return Err(internal_error(
                        id,
                        "modern MCP result _meta must be an object",
                    ));
                }
            },
        };
        meta.insert(
            META_SERVER_INFO.into(),
            implementation_value(&server.implementation),
        );

        if requires_cache_metadata(method) {
            result.insert("ttlMs".into(), serde_json::json!(0));
            result.insert("cacheScope".into(), serde_json::json!("private"));
        }

        Ok(McpWireResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: Some(
                ModernJsonRpcResponse::success(id, serde_json::Value::Object(result)).into(),
            ),
        })
    }

    fn encode_error(
        &self,
        id: ModernRequestId,
        code: i32,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> McpWireResponse {
        McpWireResponse {
            status: modern_error_status(code),
            headers: http::HeaderMap::new(),
            body: Some(ModernJsonRpcResponse::error_with_data(id, code, message, data).into()),
        }
    }
}

fn requires_cache_metadata(method: &str) -> bool {
    matches!(
        method,
        "server/discover"
            | "tools/list"
            | "prompts/list"
            | "resources/list"
            | "resources/read"
            | "resources/templates/list"
    )
}

fn modern_error_status(code: i32) -> http::StatusCode {
    match code {
        crate::mcp::types::PARSE_ERROR
        | crate::mcp::types::INVALID_REQUEST
        | crate::mcp::types::INVALID_PARAMS
        | HEADER_MISMATCH
        | MISSING_REQUIRED_CLIENT_CAPABILITY
        | UNSUPPORTED_PROTOCOL_VERSION => http::StatusCode::BAD_REQUEST,
        crate::mcp::types::METHOD_NOT_FOUND => http::StatusCode::NOT_FOUND,
        _ => http::StatusCode::OK,
    }
}

fn internal_error(id: ModernRequestId, message: &str) -> McpWireError {
    McpWireError::modern_json(
        http::StatusCode::OK,
        id,
        crate::mcp::types::INTERNAL_ERROR,
        message,
        None,
    )
}

fn validate_content_type(
    headers: &http::HeaderMap,
    id: ModernRequestId,
) -> Result<(), McpWireError> {
    let valid = header_value(headers, "content-type").is_some_and(valid_json_content_type);
    if valid {
        Ok(())
    } else {
        Err(McpWireError::modern_json(
            http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            id,
            crate::mcp::types::INVALID_REQUEST,
            "Content-Type must be application/json",
            None,
        ))
    }
}

fn validate_accept(headers: &http::HeaderMap, id: ModernRequestId) -> Result<(), McpWireError> {
    if valid_required_accept_ranges(headers) {
        Ok(())
    } else {
        Err(McpWireError::modern_json(
            http::StatusCode::NOT_ACCEPTABLE,
            id,
            crate::mcp::types::INVALID_REQUEST,
            "Accept must include application/json and text/event-stream",
            None,
        ))
    }
}

fn validate_no_duplicate_routing_headers(
    headers: &http::HeaderMap,
    id: ModernRequestId,
) -> Result<(), McpWireError> {
    for name in PROTECTED_HEADERS {
        if headers.get_all(*name).iter().nth(1).is_some() {
            return Err(header_mismatch(
                id,
                "duplicate protected MCP routing header",
            ));
        }
    }

    for (name, _) in headers {
        let name = name.as_str();
        if name.starts_with("mcp-param-") && headers.get_all(name).iter().nth(1).is_some() {
            return Err(header_mismatch(
                id,
                "duplicate MCP parameter routing header",
            ));
        }
    }
    Ok(())
}

fn required_header<'a>(
    headers: &'a http::HeaderMap,
    name: &str,
    id: ModernRequestId,
) -> Result<&'a str, McpWireError> {
    header_value(headers, name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| header_mismatch(id, "missing required MCP routing header"))
}

fn header_value<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn mirrored_params(headers: &http::HeaderMap) -> http::HeaderMap {
    let mut params = http::HeaderMap::new();
    for (name, value) in headers {
        if name.as_str().starts_with("mcp-param-") {
            params.insert(name.clone(), value.clone());
        }
    }
    params
}

fn invalid_params(id: ModernRequestId, message: &str) -> McpWireError {
    McpWireError::modern_invalid_params(id, message)
}

fn header_mismatch(id: ModernRequestId, message: &str) -> McpWireError {
    McpWireError::modern_json(
        http::StatusCode::BAD_REQUEST,
        id,
        HEADER_MISMATCH,
        message,
        None,
    )
}

fn unsupported_version(id: ModernRequestId, requested: Option<&str>) -> McpWireError {
    let data = requested.map(|requested| {
        serde_json::json!({
            "supported": [MODERN_PROTOCOL_VERSION, crate::mcp::types::LEGACY_PROTOCOL_VERSION],
            "requested": requested,
        })
    });
    McpWireError::modern_json(
        http::StatusCode::BAD_REQUEST,
        id,
        UNSUPPORTED_PROTOCOL_VERSION,
        "unsupported MCP protocol version",
        data,
    )
}

fn valid_json_content_type(value: &str) -> bool {
    let mut parser = MediaValueParser::new(value);
    let Some(type_name) = parser.token() else {
        return false;
    };
    if !parser.consume(b'/') {
        return false;
    }
    let Some(subtype) = parser.token() else {
        return false;
    };
    if !type_name.eq_ignore_ascii_case("application") || !subtype.eq_ignore_ascii_case("json") {
        return false;
    }
    parser.skip_ows();
    while !parser.is_finished() {
        if !parser.consume(b';') {
            return false;
        }
        parser.skip_ows();
        if parser.token().is_none() || !parser.consume(b'=') || !parser.parameter_value() {
            return false;
        }
        parser.skip_ows();
    }
    true
}

fn valid_required_accept_ranges(headers: &http::HeaderMap) -> bool {
    const MAX_ACCEPT_BYTES: usize = 8 * 1024;
    const MAX_NONEMPTY_MEMBERS: usize = 64;
    const MAX_EMPTY_MEMBERS: usize = 16;

    let mut combined = Vec::new();
    let mut saw_field_line = false;
    for value in headers.get_all("accept").iter() {
        if saw_field_line {
            combined.push(b',');
        }
        saw_field_line = true;
        if combined
            .len()
            .checked_add(value.as_bytes().len())
            .is_none_or(|length| length > MAX_ACCEPT_BYTES)
        {
            return false;
        }
        combined.extend_from_slice(value.as_bytes());
    }
    let Ok(combined) = std::str::from_utf8(&combined) else {
        return false;
    };

    let Ok(members) = split_accept_members(combined) else {
        return false;
    };
    let mut nonempty = 0_usize;
    let mut empty = 0_usize;
    let mut accepts_json = false;
    let mut accepts_events = false;
    for member in members {
        let member = trim_ows(member);
        if member.is_empty() {
            empty += 1;
            if empty > MAX_EMPTY_MEMBERS {
                return false;
            }
            continue;
        }
        nonempty += 1;
        if nonempty > MAX_NONEMPTY_MEMBERS {
            return false;
        }
        let Ok((json, events)) = parse_accept_member(member) else {
            return false;
        };
        accepts_json |= json;
        accepts_events |= events;
    }

    nonempty > 0 && accepts_json && accepts_events
}

fn split_accept_members(value: &str) -> Result<Vec<&str>, ()> {
    let bytes = value.as_bytes();
    let mut members = Vec::new();
    let mut start = 0_usize;
    let mut in_quote = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if in_quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_quote = false;
            }
        } else if byte == b'"' {
            in_quote = true;
        } else if byte == b',' {
            members.push(&value[start..index]);
            start = index + 1;
        }
    }
    if in_quote || escaped {
        return Err(());
    }
    members.push(&value[start..]);
    Ok(members)
}

fn parse_accept_member(member: &str) -> Result<(bool, bool), ()> {
    let mut parser = MediaValueParser::new(member);
    let type_name = parser.token().ok_or(())?;
    if !parser.consume(b'/') {
        return Err(());
    }
    let subtype = parser.token().ok_or(())?;
    let exact_json =
        type_name.eq_ignore_ascii_case("application") && subtype.eq_ignore_ascii_case("json");
    let exact_events =
        type_name.eq_ignore_ascii_case("text") && subtype.eq_ignore_ascii_case("event-stream");
    let mut quality_positive = true;
    let mut quality_seen = false;

    parser.skip_ows();
    while !parser.is_finished() {
        if !parser.consume(b';') {
            return Err(());
        }
        parser.skip_ows();
        let name = parser.token().ok_or(())?;
        if !parser.consume(b'=') {
            return Err(());
        }
        let parameter = parser.parameter().ok_or(())?;
        if name.eq_ignore_ascii_case("q") {
            if quality_seen {
                return Err(());
            }
            let ParameterValue::Token(value) = parameter else {
                return Err(());
            };
            quality_seen = true;
            quality_positive = parse_quality(value).ok_or(())?;
        }
        parser.skip_ows();
    }

    Ok((
        exact_json && quality_positive,
        exact_events && quality_positive,
    ))
}

fn parse_quality(value: &str) -> Option<bool> {
    let bytes = value.as_bytes();
    match bytes.first().copied()? {
        b'0' => {
            let fraction = bytes.get(1..).unwrap_or_default();
            if fraction.is_empty() {
                return Some(false);
            }
            if fraction.first() != Some(&b'.')
                || fraction.len() > 4
                || !fraction[1..].iter().all(u8::is_ascii_digit)
            {
                return None;
            }
            Some(fraction[1..].iter().any(|digit| *digit != b'0'))
        }
        b'1' => {
            let fraction = bytes.get(1..).unwrap_or_default();
            if fraction.is_empty() {
                return Some(true);
            }
            if fraction.first() != Some(&b'.')
                || fraction.len() > 4
                || !fraction[1..].iter().all(|digit| *digit == b'0')
            {
                return None;
            }
            Some(true)
        }
        _ => None,
    }
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t'))
}

enum ParameterValue<'a> {
    Token(&'a str),
    Quoted,
}

struct MediaValueParser<'a> {
    value: &'a str,
    position: usize,
}

impl<'a> MediaValueParser<'a> {
    fn new(value: &'a str) -> Self {
        Self { value, position: 0 }
    }

    fn token(&mut self) -> Option<&'a str> {
        let start = self.position;
        while self.peek().is_some_and(is_tchar) {
            self.position += 1;
        }
        (self.position > start).then(|| &self.value[start..self.position])
    }

    fn parameter(&mut self) -> Option<ParameterValue<'a>> {
        if self.peek() == Some(b'"') {
            self.quoted_string().then_some(ParameterValue::Quoted)
        } else {
            self.token().map(ParameterValue::Token)
        }
    }

    fn parameter_value(&mut self) -> bool {
        self.parameter().is_some()
    }

    fn quoted_string(&mut self) -> bool {
        if !self.consume(b'"') {
            return false;
        }
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.position += 1;
                    return true;
                }
                Some(b'\\') => {
                    self.position += 1;
                    match self.peek() {
                        Some(b'\t' | 0x20..=0x7e) => self.position += 1,
                        _ => return false,
                    }
                }
                Some(b'\t' | 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e) => {
                    self.position += 1;
                }
                _ => return false,
            }
        }
    }

    fn skip_ows(&mut self) {
        while self.peek().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
            self.position += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.value.as_bytes().get(self.position).copied()
    }

    fn is_finished(&self) -> bool {
        self.position == self.value.len()
    }
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

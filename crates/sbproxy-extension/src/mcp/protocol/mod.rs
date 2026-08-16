//! Protocol-neutral MCP wire codec interfaces.

use std::collections::HashSet;

pub mod contracts;
pub mod headers;
pub mod legacy;
pub mod modern;

pub use contracts::{
    build_mirrored_headers, compile_modern_tool_contract, validate_mirrored_headers,
    CompiledMcpToolContract, McpContractError, McpHeaderProjection, McpHeaderValueKind,
    McpModernToolResultDocument, McpSchemaDialect, McpSchemaLimits, McpToolContract,
    McpToolResultDocument,
};
pub use headers::{decode_header_value, encode_header_value, HeaderValueError};
pub use legacy::Legacy2025_06_18Codec;
pub use modern::{
    build_discover_result, is_recognized_modern_error, modern_server_capabilities,
    Modern2026_07_28Codec,
};

/// MCP wire-protocol era.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpProtocolEra {
    /// The frozen 2025-06-18 MCP protocol behavior.
    Legacy2025_06_18,
    /// The 2026-07-28 MCP protocol behavior.
    Modern2026_07_28,
}

/// Modern JSON scan limit that was exceeded before envelope decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawModernScanLimit {
    /// The request body exceeded one mebibyte.
    BodyBytes,
    /// JSON containers nested beyond 128 levels.
    ContainerDepth,
    /// More than 65,536 JSON values and object members were visited.
    VisitedItems,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawRootKind {
    Unknown,
    Object,
    Array,
    Other,
}

/// Duplicate-aware, bounded lexical scan of a possible modern MCP request.
#[derive(Debug, Clone)]
pub struct RawModernScan<'body> {
    body: &'body [u8],
    modern_marker: bool,
    duplicate_protected_member: bool,
    duplicate_id: bool,
    limit: Option<RawModernScanLimit>,
    syntax_valid: bool,
    root_kind: RawRootKind,
    jsonrpc_is_2_0: bool,
    method_is_string: bool,
    request_id: Result<crate::mcp::types::ModernRequestId, crate::mcp::types::ModernRequestIdError>,
}

impl<'body> RawModernScan<'body> {
    /// Scan a raw JSON body without normalizing duplicate keys or number tokens.
    pub fn scan(body: &'body [u8]) -> Self {
        if body.len() > RawJsonScanner::MAX_BODY_BYTES {
            return Self {
                body,
                modern_marker: false,
                duplicate_protected_member: false,
                duplicate_id: false,
                limit: Some(RawModernScanLimit::BodyBytes),
                syntax_valid: false,
                root_kind: RawRootKind::Unknown,
                jsonrpc_is_2_0: false,
                method_is_string: false,
                request_id: Ok(crate::mcp::types::ModernRequestId::Absent),
            };
        }

        RawJsonScanner::new(body).scan()
    }

    fn has_modern_marker(&self) -> bool {
        self.modern_marker
    }

    fn has_duplicate_protected_member(&self) -> bool {
        self.duplicate_protected_member
    }

    /// Return the first resource limit exceeded by the scan.
    pub fn limit_exceeded(&self) -> Option<RawModernScanLimit> {
        self.limit
    }

    /// Return the exact modern request identifier found on a root object.
    pub fn request_id(
        &self,
    ) -> Result<crate::mcp::types::ModernRequestId, crate::mcp::types::ModernRequestIdError> {
        if self.duplicate_id {
            Err(crate::mcp::types::ModernRequestIdError::DuplicateMember)
        } else {
            self.request_id.clone()
        }
    }

    fn usable_error_id(&self) -> crate::mcp::types::ModernRequestId {
        if !self.syntax_valid || self.root_kind != RawRootKind::Object || self.duplicate_id {
            return crate::mcp::types::ModernRequestId::Absent;
        }
        self.request_id
            .clone()
            .unwrap_or(crate::mcp::types::ModernRequestId::Absent)
    }
}

/// An MCP implementation identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct McpImplementation {
    /// Implementation name.
    pub name: String,
    /// Implementation version.
    pub version: String,
}

/// Context decoded from a protocol-specific MCP request.
#[derive(Debug, Clone, PartialEq)]
pub struct McpProtocolContext {
    /// Protocol era selected for the request.
    pub era: McpProtocolEra,
    /// Negotiated protocol version.
    pub protocol_version: String,
    /// Client capabilities advertised in `initialize`.
    pub client_capabilities: serde_json::Value,
    /// Client identity advertised in `initialize`.
    pub client_info: Option<McpImplementation>,
}

/// HTTP headers promoted into protocol routing state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpRoutingHeaders {
    /// Routing method selected by the protocol.
    pub method: Option<String>,
    /// Routing name selected by the protocol.
    pub name: Option<String>,
    /// Additional request parameters selected by the protocol.
    pub params: http::HeaderMap,
}

/// Era-specific request identifier retained after envelope decoding.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedRequestId {
    /// Frozen legacy identifier semantics, including arbitrary JSON values.
    Legacy(Option<serde_json::Value>),
    /// Strict modern identifier semantics with absent distinct from null.
    Modern(crate::mcp::types::ModernRequestId),
}

/// A decoded MCP request and its protocol context.
#[derive(Debug, Clone)]
pub struct DecodedMcpRequest {
    /// Original JSON-RPC request envelope.
    pub request: crate::mcp::types::JsonRpcRequest,
    /// Era-specific identifier used for notification and response behavior.
    pub request_id: DecodedRequestId,
    /// Protocol context extracted from the request.
    pub context: McpProtocolContext,
    /// Routing headers extracted from the request.
    pub routing_headers: McpRoutingHeaders,
}

/// Serializable response body for either frozen legacy or modern MCP.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum McpWireBody {
    /// Frozen 2025-06-18 JSON-RPC response serialization.
    Legacy(crate::mcp::types::JsonRpcResponse),
    /// Strict 2026-07-28 JSON-RPC response serialization.
    Modern(crate::mcp::types::ModernJsonRpcResponse),
}

impl From<crate::mcp::types::JsonRpcResponse> for McpWireBody {
    fn from(response: crate::mcp::types::JsonRpcResponse) -> Self {
        Self::Legacy(response)
    }
}

impl From<crate::mcp::types::ModernJsonRpcResponse> for McpWireBody {
    fn from(response: crate::mcp::types::ModernJsonRpcResponse) -> Self {
        Self::Modern(response)
    }
}

/// Protocol-specific HTTP response envelope.
#[derive(Debug, Clone)]
pub struct McpWireResponse {
    /// HTTP status code.
    pub status: http::StatusCode,
    /// HTTP response headers.
    pub headers: http::HeaderMap,
    /// Optional JSON-RPC response body.
    pub body: Option<McpWireBody>,
}

/// Protocol-specific error response envelope.
///
/// The response is boxed so that `Result<_, McpWireError>` stays small on the
/// success path; a bare `McpWireResponse` carries a `HeaderMap` and pushes
/// every wire result over the large-error threshold.
#[derive(Debug, Clone)]
pub struct McpWireError(pub Box<McpWireResponse>);

impl McpWireError {
    /// Build a JSON-RPC error response with the given HTTP status.
    pub fn json(
        status: http::StatusCode,
        id: Option<serde_json::Value>,
        code: i32,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self(Box::new(McpWireResponse {
            status,
            headers: http::HeaderMap::new(),
            body: Some(
                crate::mcp::types::JsonRpcResponse::error_with_data(id, code, message, data).into(),
            ),
        }))
    }

    /// Build a JSON-RPC invalid-params response.
    pub fn invalid_params(id: Option<serde_json::Value>, message: &str) -> Self {
        Self::json(
            http::StatusCode::BAD_REQUEST,
            id,
            crate::mcp::types::INVALID_PARAMS,
            message,
            None,
        )
    }

    /// Build a modern JSON-RPC error response with the given HTTP status.
    pub fn modern_json(
        status: http::StatusCode,
        id: crate::mcp::types::ModernRequestId,
        code: i32,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self(Box::new(McpWireResponse {
            status,
            headers: http::HeaderMap::new(),
            body: Some(
                crate::mcp::types::ModernJsonRpcResponse::error_with_data(id, code, message, data)
                    .into(),
            ),
        }))
    }

    /// Build a modern JSON-RPC invalid-params response.
    pub fn modern_invalid_params(id: crate::mcp::types::ModernRequestId, message: &str) -> Self {
        Self::modern_json(
            http::StatusCode::BAD_REQUEST,
            id,
            crate::mcp::types::INVALID_PARAMS,
            message,
            None,
        )
    }
}

/// Server properties used when encoding MCP responses.
#[derive(Debug, Clone)]
pub struct McpServerDescription {
    /// Gateway implementation identity.
    pub implementation: McpImplementation,
    /// Server capabilities.
    pub capabilities: serde_json::Value,
    /// Optional server instructions.
    pub instructions: Option<String>,
}

/// Codec for one MCP wire-protocol era.
pub trait McpProtocolCodec: Send + Sync {
    /// Era-specific request identifier accepted by response encoders.
    type RequestId: Clone;

    /// Return the wire-protocol era this codec implements.
    fn era(&self) -> McpProtocolEra;

    /// Decode an HTTP request into a JSON-RPC request and protocol context.
    fn decode_http(
        &self,
        request: crate::mcp::types::JsonRpcRequest,
        headers: &http::HeaderMap,
    ) -> Result<DecodedMcpRequest, McpWireError>;

    /// Encode a successful JSON-RPC result for this protocol era.
    fn encode_success(
        &self,
        method: &str,
        id: Self::RequestId,
        result: serde_json::Value,
        server: &McpServerDescription,
    ) -> Result<McpWireResponse, McpWireError>;

    /// Encode a JSON-RPC error for this protocol era.
    fn encode_error(
        &self,
        id: Self::RequestId,
        code: i32,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> McpWireResponse;
}

/// Select an MCP protocol era from corroborating HTTP and JSON-RPC carriers.
pub fn classify_http_era(
    scan: Option<&RawModernScan<'_>>,
    headers: &http::HeaderMap,
) -> McpProtocolEra {
    // Classify on positive modern evidence only. A request that merely fails to
    // look modern stays legacy, so the frozen 2025-06-18 path keeps answering
    // it exactly as it did before this era split existed.
    //
    // A scan that hit a structural limit is deliberately NOT modern evidence.
    // Every valid modern HTTP request carries `MCP-Protocol-Version` and
    // `Mcp-Method`, which are headers and therefore visible whatever the body
    // scan saw, so a limit alone cannot be the only sign of a modern request.
    // Treating it as one turned a large-but-valid legacy call, which serde
    // parses happily and which the 1 MiB cap already bounds, into a refusal.
    let body_marks_modern = scan.is_some_and(RawModernScan::has_modern_marker);
    let partial_routing_header = headers.contains_key("mcp-method")
        || headers.contains_key("mcp-name")
        || headers
            .keys()
            .any(|name| name.as_str().starts_with("mcp-param-"));
    // Only the exact modern revision is modern evidence. An older or unknown
    // revision is not a 2026-07-28 request, so it belongs to the legacy codec,
    // which answers it with the descriptive unsupported-version error it has
    // always returned and which still exempts `initialize` so a client can
    // negotiate down through `params.protocolVersion`.
    let modern_version = headers
        .get_all("mcp-protocol-version")
        .iter()
        .any(|value| value.as_bytes() == crate::mcp::types::MODERN_PROTOCOL_VERSION.as_bytes());

    if body_marks_modern || partial_routing_header || modern_version {
        McpProtocolEra::Modern2026_07_28
    } else {
        McpProtocolEra::Legacy2025_06_18
    }
}

/// Decode an MCP HTTP body through exactly one protocol-era codec.
pub fn decode_http_request(
    body: &[u8],
    headers: &http::HeaderMap,
) -> Result<DecodedMcpRequest, McpWireError> {
    let scan = RawModernScan::scan(body);
    decode_http_request_with_scan(&scan, headers)
}

/// Decode an MCP HTTP body while reusing a previously completed raw scan.
///
/// The scan borrows the exact body it inspected, so a caller cannot pair a
/// trusted preflight result with different bytes. This entry point lets the
/// HTTP layer classify and apply transport security before it decodes or
/// dispatches an envelope, without performing the lexical scan twice.
pub fn decode_http_request_with_scan(
    scan: &RawModernScan<'_>,
    headers: &http::HeaderMap,
) -> Result<DecodedMcpRequest, McpWireError> {
    match classify_http_era(Some(scan), headers) {
        McpProtocolEra::Legacy2025_06_18 => decode_legacy_http_request(scan.body, headers),
        McpProtocolEra::Modern2026_07_28 => decode_modern_http_request(headers, scan),
    }
}

fn decode_legacy_http_request(
    body: &[u8],
    headers: &http::HeaderMap,
) -> Result<DecodedMcpRequest, McpWireError> {
    let request: crate::mcp::types::JsonRpcRequest =
        serde_json::from_slice(body).map_err(|_| {
            let is_batch = body
                .iter()
                .find(|byte| !byte.is_ascii_whitespace())
                .is_some_and(|byte| *byte == b'[');
            let (code, message) = if is_batch {
                (
                    crate::mcp::types::INVALID_REQUEST,
                    "JSON-RPC batching is not supported (removed in MCP 2025-06-18); send one request per POST",
                )
            } else {
                (crate::mcp::types::PARSE_ERROR, "invalid JSON-RPC body")
            };
            McpWireError::json(http::StatusCode::OK, None, code, message, None)
        })?;

    if request.jsonrpc != "2.0" {
        return Err(McpWireError::json(
            http::StatusCode::OK,
            request.id,
            crate::mcp::types::INVALID_REQUEST,
            "jsonrpc field must be \"2.0\"",
            None,
        ));
    }

    Legacy2025_06_18Codec.decode_http(request, headers)
}

fn decode_modern_http_request(
    headers: &http::HeaderMap,
    scan: &RawModernScan<'_>,
) -> Result<DecodedMcpRequest, McpWireError> {
    use crate::mcp::types::{ModernRequestId, INVALID_REQUEST, PARSE_ERROR};

    if scan.limit_exceeded().is_some() {
        return Err(McpWireError::modern_json(
            http::StatusCode::BAD_REQUEST,
            ModernRequestId::Absent,
            INVALID_REQUEST,
            "modern MCP request exceeds structural scan limits",
            None,
        ));
    }
    if !scan.syntax_valid {
        return Err(McpWireError::modern_json(
            http::StatusCode::BAD_REQUEST,
            ModernRequestId::Absent,
            PARSE_ERROR,
            "invalid JSON-RPC body",
            None,
        ));
    }
    if scan.root_kind != RawRootKind::Object {
        return Err(McpWireError::modern_json(
            http::StatusCode::BAD_REQUEST,
            ModernRequestId::Absent,
            INVALID_REQUEST,
            "MCP request must be one JSON object",
            None,
        ));
    }
    if scan.has_duplicate_protected_member() {
        return Err(McpWireError::modern_json(
            http::StatusCode::BAD_REQUEST,
            scan.usable_error_id(),
            INVALID_REQUEST,
            "modern MCP request contains duplicate protected members",
            None,
        ));
    }
    if !scan.jsonrpc_is_2_0 {
        return Err(McpWireError::modern_json(
            http::StatusCode::BAD_REQUEST,
            scan.usable_error_id(),
            INVALID_REQUEST,
            "jsonrpc field must be \"2.0\"",
            None,
        ));
    }
    if !scan.method_is_string {
        return Err(McpWireError::modern_json(
            http::StatusCode::BAD_REQUEST,
            scan.usable_error_id(),
            INVALID_REQUEST,
            "method field must be a string",
            None,
        ));
    }

    let request_id = scan.request_id().map_err(|_| {
        McpWireError::modern_json(
            http::StatusCode::BAD_REQUEST,
            ModernRequestId::Absent,
            INVALID_REQUEST,
            "modern MCP request id must be a non-null string or bounded integer",
            None,
        )
    })?;
    let mut request: crate::mcp::types::JsonRpcRequest = serde_json::from_slice(scan.body)
        .map_err(|_| {
            McpWireError::modern_json(
                http::StatusCode::BAD_REQUEST,
                request_id.clone(),
                INVALID_REQUEST,
                "invalid JSON-RPC request",
                None,
            )
        })?;
    request.id = request_id.to_legacy_value();

    Modern2026_07_28Codec.decode_http_with_id(request, request_id, headers)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueScope {
    Root,
    DirectRequest,
    Params,
    Meta,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectScope {
    Request { capture_id: bool },
    Params,
    Meta,
    Opaque,
}

struct RawJsonScanner<'a> {
    body: &'a [u8],
    position: usize,
    depth: usize,
    visited: usize,
    result: RawModernScan<'a>,
}

impl<'a> RawJsonScanner<'a> {
    const MAX_BODY_BYTES: usize = 1024 * 1024;
    const MAX_CONTAINER_DEPTH: usize = 128;
    const MAX_VISITED_ITEMS: usize = 65_536;
    const RESERVED_META_PREFIX: &'static str = "io.modelcontextprotocol/";

    fn new(body: &'a [u8]) -> Self {
        Self {
            body,
            position: 0,
            depth: 0,
            visited: 0,
            result: RawModernScan {
                body,
                modern_marker: false,
                duplicate_protected_member: false,
                duplicate_id: false,
                limit: None,
                syntax_valid: false,
                root_kind: RawRootKind::Unknown,
                jsonrpc_is_2_0: false,
                method_is_string: false,
                request_id: Ok(crate::mcp::types::ModernRequestId::Absent),
            },
        }
    }

    fn scan(mut self) -> RawModernScan<'a> {
        let syntax_valid = self.parse_document().is_ok() && self.result.limit.is_none();
        self.result.syntax_valid = syntax_valid;
        self.result
    }

    fn parse_document(&mut self) -> Result<(), ()> {
        self.skip_whitespace();
        if self.position == self.body.len() {
            return Err(());
        }
        self.parse_value(ValueScope::Root)?;
        self.skip_whitespace();
        if self.position == self.body.len() {
            Ok(())
        } else {
            Err(())
        }
    }

    fn parse_value(&mut self, scope: ValueScope) -> Result<(), ()> {
        self.bump_visited()?;
        let byte = self.peek().ok_or(())?;
        if scope == ValueScope::Root {
            self.result.root_kind = match byte {
                b'{' => RawRootKind::Object,
                b'[' => RawRootKind::Array,
                _ => RawRootKind::Other,
            };
        }

        match byte {
            b'{' => {
                let object_scope = match scope {
                    ValueScope::Root => ObjectScope::Request { capture_id: true },
                    ValueScope::DirectRequest => ObjectScope::Request { capture_id: false },
                    ValueScope::Params => ObjectScope::Params,
                    ValueScope::Meta => ObjectScope::Meta,
                    ValueScope::Opaque => ObjectScope::Opaque,
                };
                self.parse_object(object_scope)
            }
            b'[' => self.parse_array(scope == ValueScope::Root),
            b'"' => self.parse_string(false).map(|_| ()),
            b't' => self.parse_literal(b"true"),
            b'f' => self.parse_literal(b"false"),
            b'n' => self.parse_literal(b"null"),
            b'-' | b'0'..=b'9' => self.parse_number_lexeme().map(|_| ()),
            _ => Err(()),
        }
    }

    fn parse_object(&mut self, scope: ObjectScope) -> Result<(), ()> {
        self.enter_container()?;
        self.expect_byte(b'{')?;
        self.skip_whitespace();
        if self.consume_if(b'}') {
            self.leave_container();
            return Ok(());
        }

        let mut protected_seen = 0_u8;
        let mut reserved_meta_seen = HashSet::new();
        loop {
            self.bump_visited()?;
            let key = self.parse_string(true)?.ok_or(())?;
            let child_scope = match scope {
                ObjectScope::Request { .. } if key == "params" => ValueScope::Params,
                ObjectScope::Params if key == "_meta" => ValueScope::Meta,
                _ => ValueScope::Opaque,
            };

            let protected_bit = match scope {
                ObjectScope::Request { .. } => request_member_bit(&key),
                ObjectScope::Params => params_member_bit(&key),
                ObjectScope::Meta | ObjectScope::Opaque => None,
            };
            let is_duplicate = protected_bit.is_some_and(|bit| {
                let duplicate = protected_seen & bit != 0;
                protected_seen |= bit;
                duplicate
            });
            if is_duplicate {
                self.result.duplicate_protected_member = true;
                if matches!(scope, ObjectScope::Request { .. }) && key == "id" {
                    self.result.duplicate_id = true;
                    self.result.request_id =
                        Err(crate::mcp::types::ModernRequestIdError::DuplicateMember);
                }
            }

            if scope == ObjectScope::Meta && key.starts_with(Self::RESERVED_META_PREFIX) {
                self.result.modern_marker = true;
                if !reserved_meta_seen.insert(key.clone()) {
                    self.result.duplicate_protected_member = true;
                }
            }

            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_whitespace();
            let capture_id = matches!(scope, ObjectScope::Request { capture_id: true })
                && key == "id"
                && !is_duplicate;
            let capture_jsonrpc = matches!(scope, ObjectScope::Request { capture_id: true })
                && key == "jsonrpc"
                && !is_duplicate;
            let capture_method = matches!(scope, ObjectScope::Request { capture_id: true })
                && key == "method"
                && !is_duplicate;
            if capture_id {
                let request_id = self.parse_request_id()?;
                self.result.request_id = request_id;
            } else if capture_jsonrpc {
                self.result.jsonrpc_is_2_0 = self.parse_string_member(Some("2.0"))?;
            } else if capture_method {
                self.result.method_is_string = self.parse_string_member(None)?;
            } else {
                self.parse_value(child_scope)?;
            }
            self.skip_whitespace();

            if self.consume_if(b'}') {
                self.leave_container();
                return Ok(());
            }
            self.expect_byte(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self, top_level_batch: bool) -> Result<(), ()> {
        self.enter_container()?;
        self.expect_byte(b'[')?;
        self.skip_whitespace();
        if self.consume_if(b']') {
            self.leave_container();
            return Ok(());
        }

        loop {
            let child_scope = if top_level_batch {
                ValueScope::DirectRequest
            } else {
                ValueScope::Opaque
            };
            self.parse_value(child_scope)?;
            self.skip_whitespace();
            if self.consume_if(b']') {
                self.leave_container();
                return Ok(());
            }
            self.expect_byte(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_request_id(
        &mut self,
    ) -> Result<
        Result<crate::mcp::types::ModernRequestId, crate::mcp::types::ModernRequestIdError>,
        (),
    > {
        use crate::mcp::types::{McpInteger, ModernRequestId, ModernRequestIdError};

        match self.peek().ok_or(())? {
            b'"' => {
                self.bump_visited()?;
                let value = self.parse_string(true)?.ok_or(())?;
                Ok(Ok(ModernRequestId::String(value)))
            }
            b'-' | b'0'..=b'9' => {
                self.bump_visited()?;
                let range = self.parse_number_lexeme()?;
                let token = std::str::from_utf8(&self.body[range]).map_err(|_| ())?;
                if token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                    return Ok(Err(ModernRequestIdError::NonIntegerNumber));
                }
                if token.starts_with('-') {
                    Ok(token
                        .parse::<i64>()
                        .map(|value| ModernRequestId::Integer(McpInteger::Signed(value)))
                        .map_err(|_| ModernRequestIdError::IntegerOutOfRange))
                } else {
                    Ok(token
                        .parse::<u64>()
                        .map(|value| ModernRequestId::Integer(McpInteger::Unsigned(value)))
                        .map_err(|_| ModernRequestIdError::IntegerOutOfRange))
                }
            }
            b'n' => {
                self.parse_value(ValueScope::Opaque)?;
                Ok(Err(ModernRequestIdError::ExplicitNull))
            }
            _ => {
                self.parse_value(ValueScope::Opaque)?;
                Ok(Err(ModernRequestIdError::InvalidType))
            }
        }
    }

    fn parse_string_member(&mut self, expected: Option<&str>) -> Result<bool, ()> {
        if self.peek() != Some(b'"') {
            self.parse_value(ValueScope::Opaque)?;
            return Ok(false);
        }
        self.bump_visited()?;
        let value = self.parse_string(true)?.ok_or(())?;
        Ok(expected.is_none_or(|expected| value == expected))
    }

    fn parse_string(&mut self, capture: bool) -> Result<Option<String>, ()> {
        self.expect_byte(b'"')?;
        let mut decoded = capture.then(Vec::new);
        loop {
            let byte = self.peek().ok_or(())?;
            match byte {
                b'"' => {
                    self.position += 1;
                    return decoded
                        .map(|bytes| String::from_utf8(bytes).map_err(|_| ()))
                        .transpose();
                }
                b'\\' => {
                    self.position += 1;
                    let escaped = self.peek().ok_or(())?;
                    self.position += 1;
                    match escaped {
                        b'"' | b'\\' | b'/' => push_decoded_byte(&mut decoded, escaped),
                        b'b' => push_decoded_byte(&mut decoded, 0x08),
                        b'f' => push_decoded_byte(&mut decoded, 0x0c),
                        b'n' => push_decoded_byte(&mut decoded, b'\n'),
                        b'r' => push_decoded_byte(&mut decoded, b'\r'),
                        b't' => push_decoded_byte(&mut decoded, b'\t'),
                        b'u' => {
                            let first = self.parse_hex_quad()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                self.expect_byte(b'\\')?;
                                self.expect_byte(b'u')?;
                                let second = self.parse_hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(());
                                }
                                0x1_0000
                                    + (((first as u32) - 0xd800) << 10)
                                    + ((second as u32) - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err(());
                            } else {
                                first as u32
                            };
                            let character = char::from_u32(scalar).ok_or(())?;
                            if let Some(bytes) = decoded.as_mut() {
                                let mut buffer = [0_u8; 4];
                                bytes.extend_from_slice(
                                    character.encode_utf8(&mut buffer).as_bytes(),
                                );
                            }
                        }
                        _ => return Err(()),
                    }
                }
                0x00..=0x1f => return Err(()),
                0x20..=0x7f => {
                    push_decoded_byte(&mut decoded, byte);
                    self.position += 1;
                }
                _ => {
                    let width = utf8_sequence_width(byte).ok_or(())?;
                    let end = self.position.checked_add(width).ok_or(())?;
                    let sequence = self.body.get(self.position..end).ok_or(())?;
                    std::str::from_utf8(sequence).map_err(|_| ())?;
                    if let Some(bytes) = decoded.as_mut() {
                        bytes.extend_from_slice(sequence);
                    }
                    self.position = end;
                }
            }
        }
    }

    fn parse_hex_quad(&mut self) -> Result<u16, ()> {
        let end = self.position.checked_add(4).ok_or(())?;
        let digits = self.body.get(self.position..end).ok_or(())?;
        let mut value = 0_u16;
        for digit in digits {
            value = value.checked_mul(16).ok_or(())?;
            value = value.checked_add(hex_value(*digit).ok_or(())?).ok_or(())?;
        }
        self.position = end;
        Ok(value)
    }

    fn parse_number_lexeme(&mut self) -> Result<std::ops::Range<usize>, ()> {
        let start = self.position;
        self.consume_if(b'-');
        match self.peek().ok_or(())? {
            b'0' => {
                self.position += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(());
                }
            }
            b'1'..=b'9' => {
                self.position += 1;
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.position += 1;
                }
            }
            _ => return Err(()),
        }

        if self.consume_if(b'.') {
            if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(());
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
        }
        if self.peek().is_some_and(|byte| matches!(byte, b'e' | b'E')) {
            self.position += 1;
            if self.peek().is_some_and(|byte| matches!(byte, b'+' | b'-')) {
                self.position += 1;
            }
            if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(());
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
        }

        Ok(start..self.position)
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), ()> {
        let end = self.position.checked_add(literal.len()).ok_or(())?;
        if self.body.get(self.position..end) != Some(literal) {
            return Err(());
        }
        self.position = end;
        Ok(())
    }

    fn enter_container(&mut self) -> Result<(), ()> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > Self::MAX_CONTAINER_DEPTH {
            self.set_limit(RawModernScanLimit::ContainerDepth);
            Err(())
        } else {
            Ok(())
        }
    }

    fn leave_container(&mut self) {
        self.depth -= 1;
    }

    fn bump_visited(&mut self) -> Result<(), ()> {
        self.visited = self.visited.saturating_add(1);
        if self.visited > Self::MAX_VISITED_ITEMS {
            self.set_limit(RawModernScanLimit::VisitedItems);
            Err(())
        } else {
            Ok(())
        }
    }

    fn set_limit(&mut self, limit: RawModernScanLimit) {
        if self.result.limit.is_none() {
            self.result.limit = Some(limit);
        }
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.body.get(self.position).copied()
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), ()> {
        if self.consume_if(expected) {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn request_member_bit(key: &str) -> Option<u8> {
    match key {
        "jsonrpc" => Some(1 << 0),
        "id" => Some(1 << 1),
        "method" => Some(1 << 2),
        "params" => Some(1 << 3),
        _ => None,
    }
}

fn params_member_bit(key: &str) -> Option<u8> {
    match key {
        "_meta" => Some(1 << 0),
        "name" => Some(1 << 1),
        "uri" => Some(1 << 2),
        "arguments" => Some(1 << 3),
        "cursor" => Some(1 << 4),
        _ => None,
    }
}

fn push_decoded_byte(decoded: &mut Option<Vec<u8>>, byte: u8) {
    if let Some(bytes) = decoded.as_mut() {
        bytes.push(byte);
    }
}

fn utf8_sequence_width(first: u8) -> Option<usize> {
    match first {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

fn hex_value(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u16),
        b'a'..=b'f' => Some((byte - b'a' + 10) as u16),
        b'A'..=b'F' => Some((byte - b'A' + 10) as u16),
        _ => None,
    }
}

//! WebSocket action handler.
//!
//! Proxies incoming HTTP requests to an upstream WebSocket server.
//! Supports ws:// and wss:// URL schemes, optional subprotocol
//! negotiation, and configurable max message size.

use serde::Deserialize;

use super::ForwardingHeaderControls;

/// Message payload ceiling a `websocket` action gets when it does not
/// configure `max_message_size`, and the ceiling every other upgraded
/// tunnel gets when it does not configure one either.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Largest payload RFC 6455 section 5.5 permits on a control frame.
pub const MAX_CONTROL_FRAME_PAYLOAD: u64 = 125;

pub(crate) fn default_max_message_size() -> usize {
    DEFAULT_MAX_MESSAGE_SIZE
}

/// Wire limit a tunnel scanner enforces. `0` means no ceiling, which is
/// how an operator says they want an unbounded tunnel rather than the
/// documented 10 MB default.
pub(crate) fn tunnel_limit_bytes(max_message_size: usize) -> u64 {
    if max_message_size == 0 {
        u64::MAX
    } else {
        max_message_size as u64
    }
}

/// WebSocket action config - proxies requests to an upstream WebSocket server.
#[derive(Debug, Deserialize)]
pub struct WebSocketAction {
    /// Backend WebSocket URL (ws:// or wss://).
    pub url: String,
    /// Supported subprotocols for negotiation.
    #[serde(default)]
    pub subprotocols: Vec<String>,
    /// Maximum message payload size in bytes (default: 10 MB).
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    /// Override the `Host` header sent on the upgrade request. Defaults to
    /// the upstream URL's hostname, which is what most vhost-based servers
    /// expect. Set this if the upstream needs a different Host.
    #[serde(default)]
    pub host_override: Option<String>,
    /// Per-action opt-out flags for the standard proxy forwarding headers.
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
}

impl WebSocketAction {
    /// Build a WebSocketAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Parse the WebSocket URL into (host, port, tls) for upstream peer.
    ///
    /// Converts ws:// to http:// and wss:// to https:// before parsing
    /// so that the standard URL parser can extract host and port.
    pub fn parse_upstream(&self) -> anyhow::Result<(String, u16, bool)> {
        super::memoized_upstream(&self.url, || {
            let normalized = if self.url.starts_with("wss://") {
                self.url.replacen("wss://", "https://", 1)
            } else if self.url.starts_with("ws://") {
                self.url.replacen("ws://", "http://", 1)
            } else {
                self.url.clone()
            };

            let parsed = url::Url::parse(&normalized)?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host in websocket URL"))?
                .to_string();
            let tls = parsed.scheme() == "https";
            let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
            Ok((host, port, tls))
        })
    }
}

impl WebSocketAction {
    /// The subset of the client's offered subprotocols this action permits,
    /// preserving the client's preference order.
    ///
    /// Returns `None` when the action configures no `subprotocols`, which
    /// means negotiation passes through untouched (the pre-enforcement
    /// behavior). Comparison is case-sensitive, as RFC 6455 subprotocol
    /// tokens are.
    pub fn permitted_subprotocols(&self, offered: &[String]) -> Option<Vec<String>> {
        if self.subprotocols.is_empty() {
            return None;
        }
        Some(
            offered
                .iter()
                .filter(|offer| self.subprotocols.iter().any(|allowed| allowed == *offer))
                .cloned()
                .collect(),
        )
    }
}

/// Split `Sec-WebSocket-Protocol` header values into individual subprotocol
/// tokens, preserving order.
///
/// A client may send the offer as one comma-separated header or as several
/// headers; both forms produce the same token list here. Empty entries
/// produced by stray commas or whitespace are dropped.
pub fn parse_subprotocol_header_values<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    values
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

/// A frame on an upgraded tunnel crossed one of the limits the gateway
/// enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameViolation {
    /// A data message crossed the configured `max_message_size`.
    MessageTooLarge {
        /// Total payload bytes the message had declared when the cap
        /// tripped, summed across continuation fragments.
        observed: u64,
        /// The configured `max_message_size` in bytes.
        limit: u64,
    },
    /// A control frame declared more payload than RFC 6455 section 5.5
    /// permits.
    ///
    /// Control frames do not count toward a data message's total, so
    /// their declared length is skipped rather than accumulated. That
    /// makes an unchecked length load bearing twice over: the upstream
    /// is handed a control frame it may allocate for before validating,
    /// and the scanner would spend the declared count skipping payload
    /// bytes, so a `u64::MAX` pong header wedges it for the life of the
    /// connection and `max_message_size` stops applying to anything.
    OversizedControlFrame {
        /// Payload length the frame header declared.
        declared: u64,
    },
    /// A control frame arrived without `FIN`. RFC 6455 section 5.5
    /// forbids fragmenting control frames, and a continuation of one
    /// has no defined reassembly.
    FragmentedControlFrame {
        /// Opcode of the frame that arrived fragmented.
        opcode: u8,
    },
}

impl FrameViolation {
    /// Stable label for logs, metrics, and the teardown's error type.
    pub fn label(&self) -> &'static str {
        match self {
            Self::MessageTooLarge { .. } => "websocket_message_too_large",
            Self::OversizedControlFrame { .. } => "websocket_oversized_control_frame",
            Self::FragmentedControlFrame { .. } => "websocket_fragmented_control_frame",
        }
    }
}

impl std::fmt::Display for FrameViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageTooLarge { observed, limit } => write!(
                f,
                "websocket message of {observed} bytes exceeds max_message_size {limit}"
            ),
            Self::OversizedControlFrame { declared } => write!(
                f,
                "websocket control frame declares {declared} payload bytes; RFC 6455 permits at \
                 most {MAX_CONTROL_FRAME_PAYLOAD}"
            ),
            Self::FragmentedControlFrame { opcode } => write!(
                f,
                "websocket control frame with opcode 0x{opcode:X} arrived fragmented; RFC 6455 \
                 forbids fragmenting control frames"
            ),
        }
    }
}

/// Streaming RFC 6455 frame-header scanner enforcing a maximum message
/// payload size for one direction of a tunnel.
///
/// The scanner never buffers payload bytes: it parses each frame header
/// (tolerating headers split across arbitrary chunk boundaries), sums the
/// declared payload lengths of a data message across its continuation
/// fragments, and reports a violation as soon as the running total crosses
/// the cap, before the payload itself has fully arrived. Control frames
/// (opcodes `0x8`-`0xF`) interleave freely and never count toward a data
/// message's size. The cap applies to payload bytes as carried on the wire,
/// which is the compressed size when the endpoints negotiated
/// `permessage-deflate`.
#[derive(Debug)]
struct FrameSizeScanner {
    limit: u64,
    header: [u8; 14],
    header_len: usize,
    remaining_payload: u64,
    message_bytes: u64,
    message_complete: bool,
}

impl FrameSizeScanner {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            header: [0; 14],
            header_len: 0,
            remaining_payload: 0,
            message_bytes: 0,
            message_complete: true,
        }
    }

    fn scan(&mut self, bytes: &[u8]) -> Result<(), FrameViolation> {
        let mut input = bytes;
        while !input.is_empty() {
            if self.remaining_payload > 0 {
                let take = usize::try_from(self.remaining_payload)
                    .unwrap_or(usize::MAX)
                    .min(input.len());
                self.remaining_payload -= take as u64;
                input = &input[take..];
                continue;
            }
            // Assemble the frame header byte by byte; a header is at most
            // 14 bytes and may arrive split across any chunk boundary.
            self.header[self.header_len] = input[0];
            self.header_len += 1;
            input = &input[1..];
            let Some((payload_len, opcode, fin)) =
                parse_frame_header(&self.header[..self.header_len])
            else {
                continue;
            };
            self.header_len = 0;
            // Control frames (opcode high bit set: close, ping, pong, and
            // the reserved control opcodes) may interleave with a
            // fragmented message and never count toward it. Because their
            // declared length is skipped rather than accumulated, it has
            // to be checked here or it is never checked at all: RFC 6455
            // section 5.5 caps a control frame at 125 payload bytes and
            // forbids fragmenting one, and both rules are refused before
            // `remaining_payload` is set from a length already rejected.
            if opcode & 0x8 != 0 {
                if payload_len > MAX_CONTROL_FRAME_PAYLOAD {
                    return Err(FrameViolation::OversizedControlFrame {
                        declared: payload_len,
                    });
                }
                if !fin {
                    return Err(FrameViolation::FragmentedControlFrame { opcode });
                }
                self.remaining_payload = payload_len;
                continue;
            }
            self.remaining_payload = payload_len;
            // A non-continuation opcode, or any data frame after a FIN,
            // starts a new message.
            if opcode != 0x0 || self.message_complete {
                self.message_bytes = 0;
            }
            self.message_bytes = self.message_bytes.saturating_add(payload_len);
            self.message_complete = fin;
            if self.message_bytes > self.limit {
                return Err(FrameViolation::MessageTooLarge {
                    observed: self.message_bytes,
                    limit: self.limit,
                });
            }
        }
        Ok(())
    }
}

/// Parse a complete RFC 6455 frame header from `bytes`, returning
/// `(payload_len, opcode, fin)`, or `None` when more bytes are needed.
fn parse_frame_header(bytes: &[u8]) -> Option<(u64, u8, bool)> {
    if bytes.len() < 2 {
        return None;
    }
    let masked = bytes[1] & 0x80 != 0;
    let len7 = bytes[1] & 0x7F;
    let extended = match len7 {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let need = 2 + extended + if masked { 4 } else { 0 };
    if bytes.len() < need {
        return None;
    }
    let payload_len = match len7 {
        126 => u64::from(u16::from_be_bytes([bytes[2], bytes[3]])),
        127 => u64::from_be_bytes([
            bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
        ]),
        n => u64::from(n),
    };
    Some((payload_len, bytes[0] & 0x0F, bytes[0] & 0x80 != 0))
}

/// Message-size enforcement state for an upgraded WebSocket tunnel.
///
/// Armed on the request context when a `websocket` action's upgrade
/// completes (`101 Switching Protocols`). Each direction is scanned
/// independently, because `max_message_size` bounds what either peer may
/// send. After a violation the guard stays tripped: the tunnel is being
/// torn down and no further bytes should be forwarded.
#[derive(Debug)]
pub struct WebSocketTunnelGuard {
    client_to_upstream: FrameSizeScanner,
    upstream_to_client: FrameSizeScanner,
    violation: Option<FrameViolation>,
}

impl WebSocketTunnelGuard {
    /// Build a guard enforcing `max_message_size` bytes per message in each
    /// direction.
    pub fn new(max_message_size: usize) -> Self {
        let limit = tunnel_limit_bytes(max_message_size);
        Self {
            client_to_upstream: FrameSizeScanner::new(limit),
            upstream_to_client: FrameSizeScanner::new(limit),
            violation: None,
        }
    }

    /// Scan client-to-upstream tunnel bytes.
    pub fn scan_client_bytes(&mut self, bytes: &[u8]) -> Result<(), FrameViolation> {
        if let Some(violation) = self.violation {
            return Err(violation);
        }
        self.client_to_upstream
            .scan(bytes)
            .inspect_err(|violation| {
                self.violation = Some(*violation);
            })
    }

    /// Scan upstream-to-client tunnel bytes.
    pub fn scan_upstream_bytes(&mut self, bytes: &[u8]) -> Result<(), FrameViolation> {
        if let Some(violation) = self.violation {
            return Err(violation);
        }
        self.upstream_to_client
            .scan(bytes)
            .inspect_err(|violation| {
                self.violation = Some(*violation);
            })
    }

    /// Whether either direction has already violated the cap.
    pub fn violated(&self) -> bool {
        self.violation.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_from_config_full() {
        let json = serde_json::json!({
            "type": "websocket",
            "url": "wss://echo.example.com/ws",
            "subprotocols": ["graphql-ws", "graphql-transport-ws"],
            "max_message_size": 5242880
        });
        let ws = WebSocketAction::from_config(json).unwrap();
        assert_eq!(ws.url, "wss://echo.example.com/ws");
        assert_eq!(ws.subprotocols, vec!["graphql-ws", "graphql-transport-ws"]);
        assert_eq!(ws.max_message_size, 5_242_880);
    }

    #[test]
    fn websocket_from_config_defaults() {
        let json = serde_json::json!({
            "type": "websocket",
            "url": "ws://localhost:8080"
        });
        let ws = WebSocketAction::from_config(json).unwrap();
        assert!(ws.subprotocols.is_empty());
        assert_eq!(ws.max_message_size, 10 * 1024 * 1024);
    }

    #[test]
    fn a_zero_max_message_size_is_an_unbounded_tunnel() {
        let json = serde_json::json!({
            "type": "websocket",
            "url": "ws://localhost:8080",
            "max_message_size": 0
        });
        let ws = WebSocketAction::from_config(json).unwrap();
        assert_eq!(ws.max_message_size, 0);
        let mut guard = WebSocketTunnelGuard::new(0);
        // 50 MB would trip the 10 MB default; 0 must let it through.
        let header = {
            let mut bytes = vec![0x81u8, 127];
            bytes.extend_from_slice(&(50 * 1024 * 1024u64).to_be_bytes());
            bytes
        };
        guard
            .scan_client_bytes(&header)
            .expect("max_message_size 0 means no payload ceiling");
    }

    #[test]
    fn websocket_from_config_missing_url() {
        let json = serde_json::json!({"type": "websocket"});
        assert!(WebSocketAction::from_config(json).is_err());
    }

    #[test]
    fn parse_upstream_ws() {
        let ws = WebSocketAction {
            url: "ws://backend:9090/ws".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = ws.parse_upstream().unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 9090);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_wss_default_port() {
        let ws = WebSocketAction {
            url: "wss://secure.example.com/stream".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = ws.parse_upstream().unwrap();
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_ws_default_port() {
        let ws = WebSocketAction {
            url: "ws://localhost".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = ws.parse_upstream().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_http_url() {
        let ws = WebSocketAction {
            url: "http://fallback:3000".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = ws.parse_upstream().unwrap();
        assert_eq!(host, "fallback");
        assert_eq!(port, 3000);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_invalid_url() {
        let ws = WebSocketAction {
            url: "not a valid url".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        assert!(ws.parse_upstream().is_err());
    }

    // --- Subprotocol negotiation helpers (WOR-2490) ---

    fn action_with_subprotocols(subprotocols: &[&str]) -> WebSocketAction {
        WebSocketAction {
            url: "ws://backend:9090/ws".to_string(),
            subprotocols: subprotocols.iter().map(|s| s.to_string()).collect(),
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        }
    }

    fn offers(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_subprotocol_values_splits_commas_and_multiple_headers() {
        let parsed =
            parse_subprotocol_header_values(["chat.v1, chat.v2", " chat.v3 ", "", " , chat.v4"]);
        assert_eq!(
            parsed,
            offers(&["chat.v1", "chat.v2", "chat.v3", "chat.v4"])
        );
    }

    #[test]
    fn permitted_subprotocols_none_when_unconfigured() {
        let ws = action_with_subprotocols(&[]);
        assert_eq!(ws.permitted_subprotocols(&offers(&["chat.v1"])), None);
    }

    #[test]
    fn permitted_subprotocols_filters_preserving_client_order() {
        let ws = action_with_subprotocols(&["chat.v2", "chat.v1"]);
        let permitted = ws
            .permitted_subprotocols(&offers(&["chat.v1", "chat.v3", "chat.v2"]))
            .expect("configured subprotocols must produce a filtered offer");
        assert_eq!(permitted, offers(&["chat.v1", "chat.v2"]));
    }

    #[test]
    fn permitted_subprotocols_is_case_sensitive() {
        // RFC 6455 subprotocol tokens are case-sensitive; `Chat.V1` must
        // not satisfy a `chat.v1` allowlist.
        let ws = action_with_subprotocols(&["chat.v1"]);
        let permitted = ws
            .permitted_subprotocols(&offers(&["Chat.V1"]))
            .expect("configured subprotocols must produce a filtered offer");
        assert!(permitted.is_empty(), "got {permitted:?}");
    }

    // --- Frame-size scanning (WOR-2490) ---

    /// Build one frame's wire bytes: header plus a zero-filled payload.
    fn frame(fin: bool, opcode: u8, masked: bool, payload_len: usize) -> Vec<u8> {
        let mut bytes = vec![if fin { 0x80 | opcode } else { opcode }];
        let mask_bit = if masked { 0x80 } else { 0x00 };
        if payload_len < 126 {
            bytes.push(mask_bit | payload_len as u8);
        } else if payload_len <= u16::MAX as usize {
            bytes.push(mask_bit | 126);
            bytes.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            bytes.push(mask_bit | 127);
            bytes.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }
        if masked {
            bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        }
        bytes.extend(std::iter::repeat_n(0u8, payload_len));
        bytes
    }

    #[test]
    fn tunnel_guard_passes_messages_at_or_under_the_cap() {
        let mut guard = WebSocketTunnelGuard::new(1024);
        // Repeated messages at exactly the cap: the accumulator must reset
        // at each FIN instead of summing across messages.
        for _ in 0..3 {
            guard
                .scan_client_bytes(&frame(true, 0x1, true, 1024))
                .expect("message at the cap must pass");
        }
        assert!(!guard.violated());
    }

    #[test]
    fn tunnel_guard_refuses_a_single_oversized_frame() {
        let mut guard = WebSocketTunnelGuard::new(1024);
        let violation = guard
            .scan_client_bytes(&frame(true, 0x1, true, 1025))
            .expect_err("frame over the cap must be refused");
        assert_eq!(
            violation,
            FrameViolation::MessageTooLarge {
                observed: 1025,
                limit: 1024
            }
        );
        assert!(guard.violated());
    }

    #[test]
    fn tunnel_guard_refuses_before_the_payload_arrives() {
        // The header alone declares the violation; enforcement must not
        // wait for (or forward) the payload bytes.
        let mut guard = WebSocketTunnelGuard::new(1024);
        let oversized = frame(true, 0x2, true, 4096);
        let header_only = &oversized[..8];
        guard
            .scan_client_bytes(header_only)
            .expect_err("declared oversize must trip on the header");
    }

    #[test]
    fn tunnel_guard_accumulates_continuation_fragments() {
        let mut guard = WebSocketTunnelGuard::new(1024);
        guard
            .scan_client_bytes(&frame(false, 0x1, true, 600))
            .expect("first fragment under the cap");
        let violation = guard
            .scan_client_bytes(&frame(true, 0x0, true, 600))
            .expect_err("fragments summing over the cap must be refused");
        assert_eq!(
            violation,
            FrameViolation::MessageTooLarge {
                observed: 1200,
                limit: 1024
            }
        );
    }

    #[test]
    fn tunnel_guard_ignores_interleaved_control_frames() {
        let mut guard = WebSocketTunnelGuard::new(1024);
        guard
            .scan_client_bytes(&frame(false, 0x1, true, 600))
            .expect("first fragment");
        // A ping between fragments (RFC 6455 permits this) must not count
        // toward the data message, and must not reset the accumulator.
        guard
            .scan_client_bytes(&frame(true, 0x9, true, 125))
            .expect("control frame");
        guard
            .scan_client_bytes(&frame(true, 0x0, true, 400))
            .expect("total stays under the cap");
        guard
            .scan_client_bytes(&frame(false, 0x1, true, 600))
            .expect("next message starts fresh");
        guard
            .scan_client_bytes(&frame(true, 0x0, true, 600))
            .expect_err("next message crossing the cap must be refused");
    }

    #[test]
    fn tunnel_guard_handles_headers_split_across_chunks() {
        let mut guard = WebSocketTunnelGuard::new(1024);
        let oversized = frame(true, 0x1, true, 70_000);
        // Feed the wire bytes one at a time; the 64-bit extended length
        // spans several chunks and must still be assembled and refused.
        let mut violated = false;
        for byte in &oversized[..14] {
            if guard.scan_client_bytes(std::slice::from_ref(byte)).is_err() {
                violated = true;
                break;
            }
        }
        assert!(violated, "split header must still trip the cap");
    }

    #[test]
    fn tunnel_guard_scans_unmasked_server_frames() {
        // Server-to-client frames carry no masking key; the header is four
        // bytes shorter and the direction must still be enforced.
        let mut guard = WebSocketTunnelGuard::new(1024);
        guard
            .scan_upstream_bytes(&frame(true, 0x1, false, 1024))
            .expect("server message at the cap");
        guard
            .scan_upstream_bytes(&frame(true, 0x1, false, 1025))
            .expect_err("server message over the cap must be refused");
    }

    #[test]
    fn tunnel_guard_tracks_frames_across_payload_boundaries() {
        let mut guard = WebSocketTunnelGuard::new(1024);
        // Two under-cap messages delivered in one chunk, then a split where
        // a chunk ends mid-payload and the next begins with a fresh header.
        let mut wire = frame(true, 0x1, true, 200);
        wire.extend(frame(true, 0x1, true, 300));
        guard.scan_client_bytes(&wire).expect("two small messages");
        let big = frame(true, 0x2, true, 500);
        guard
            .scan_client_bytes(&big[..40])
            .expect("partial payload");
        let mut rest = big[40..].to_vec();
        rest.extend(frame(true, 0x1, true, 2000));
        guard
            .scan_client_bytes(&rest)
            .expect_err("frame after the split payload must still be parsed");
    }

    #[test]
    fn tunnel_guard_stays_tripped_after_a_violation() {
        let mut guard = WebSocketTunnelGuard::new(64);
        guard
            .scan_client_bytes(&frame(true, 0x1, true, 65))
            .expect_err("violation");
        guard
            .scan_client_bytes(&frame(true, 0x1, true, 1))
            .expect_err("guard must stay tripped once violated");
        guard
            .scan_upstream_bytes(&frame(true, 0x1, false, 1))
            .expect_err("the other direction is torn down with the tunnel");
    }

    #[test]
    fn tunnel_guard_sixteen_bit_extended_length() {
        let mut guard = WebSocketTunnelGuard::new(300);
        guard
            .scan_client_bytes(&frame(true, 0x1, true, 300))
            .expect("16-bit length at the cap");
        guard
            .scan_client_bytes(&frame(true, 0x1, true, 301))
            .expect_err("16-bit length over the cap");
    }

    /// The exact fourteen bytes from the retrospective review of PR
    /// #1148: a masked pong header declaring `u64::MAX` payload, and
    /// nothing after it.
    ///
    /// ```text
    /// 8A FF  FF FF FF FF FF FF FF FF  11 22 33 44
    /// ^  ^   \_____ 64-bit declared length = u64::MAX ____/  \_ mask _/
    /// |  +-- MASK=1, len7=127
    /// +----- FIN=1, opcode=0xA (pong)
    /// ```
    const WEDGING_PONG_HEADER: [u8; 14] = [
        0x8A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44,
    ];

    #[test]
    fn tunnel_guard_refuses_a_control_frame_over_the_rfc_limit() {
        let mut guard = WebSocketTunnelGuard::new(1_048_576);
        let violation = guard
            .scan_client_bytes(&WEDGING_PONG_HEADER)
            .expect_err("a control frame declaring u64::MAX must be refused");
        assert_eq!(
            violation,
            FrameViolation::OversizedControlFrame { declared: u64::MAX }
        );
        assert!(guard.violated());
    }

    #[test]
    fn a_bogus_control_frame_length_cannot_wedge_the_scanner() {
        // Before the fix this was the whole attack: the pong's declared
        // length was written into `remaining_payload` and the cap check
        // was skipped, so every later byte was consumed as payload, no
        // frame header was ever parsed again, and `max_message_size`
        // was inert for the life of the tunnel while `violated()` stayed
        // false.
        let mut guard = WebSocketTunnelGuard::new(1_048_576);
        let mut wire = WEDGING_PONG_HEADER.to_vec();
        wire.extend(frame(true, 0x1, true, 2 * 1_048_576));

        guard
            .scan_client_bytes(&wire)
            .expect_err("the oversized message behind the pong must still be seen");
        assert!(
            guard.violated(),
            "the guard must trip, so `fail_to_proxy` tears the tunnel down"
        );
    }

    #[test]
    fn tunnel_guard_refuses_a_fragmented_control_frame() {
        let mut guard = WebSocketTunnelGuard::new(1024);
        let violation = guard
            .scan_client_bytes(&frame(false, 0x9, true, 4))
            .expect_err("RFC 6455 forbids fragmenting a control frame");
        assert_eq!(
            violation,
            FrameViolation::FragmentedControlFrame { opcode: 0x9 }
        );
    }

    #[test]
    fn tunnel_guard_allows_a_control_frame_at_the_rfc_limit() {
        // 125 is legal and must stay legal: the ping/pong keepalives a
        // working tunnel relies on carry real payloads.
        let mut guard = WebSocketTunnelGuard::new(1024);
        guard
            .scan_client_bytes(&frame(true, 0xA, true, 125))
            .expect("a 125-byte pong is exactly at the RFC ceiling");
        guard
            .scan_client_bytes(&frame(true, 0x8, true, 2))
            .expect("a close frame carrying a status code");
        assert!(!guard.violated());
    }
}

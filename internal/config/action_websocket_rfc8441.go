package config

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

func isRFC8441WebSocketRequest(r *http.Request) bool {
	return r != nil &&
		r.Method == http.MethodConnect &&
		r.ProtoMajor == 2 &&
		strings.EqualFold(r.Header.Get(":protocol"), "websocket")
}

// isRFC9220WebSocketRequest detects WebSocket-over-HTTP/3 extended CONNECT
// requests per RFC 9220. The mechanism mirrors RFC 8441 but runs over QUIC.
func isRFC9220WebSocketRequest(r *http.Request) bool {
	return r != nil &&
		r.Method == http.MethodConnect &&
		r.ProtoMajor == 3 &&
		strings.EqualFold(r.Header.Get(":protocol"), "websocket")
}

// isExtendedConnectWebSocketRequest returns true for both RFC 8441 (HTTP/2)
// and RFC 9220 (HTTP/3) extended CONNECT WebSocket requests.
func isExtendedConnectWebSocketRequest(r *http.Request) bool {
	return isRFC8441WebSocketRequest(r) || isRFC9220WebSocketRequest(r)
}

// handleExtendedConnectWebSocket handles WebSocket-over-HTTP/2 (RFC 8441) and
// WebSocket-over-HTTP/3 (RFC 9220) requests. Both RFCs use the same extended
// CONNECT mechanism; only the transport layer differs.
func (c *WebSocketAction) handleExtendedConnectWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor == 3 && !c.EnableRFC9220 {
		http.Error(w, "RFC 9220 websocket-over-HTTP/3 support is disabled", http.StatusNotImplemented)
		return
	}
	if r.ProtoMajor == 2 && !c.EnableRFC8441 {
		http.Error(w, "RFC 8441 websocket-over-HTTP/2 support is disabled", http.StatusNotImplemented)
		return
	}

	startTime := time.Now()
	origin := c.URL
	if origin == "" {
		origin = "unknown"
	}

	backendURL := c.buildBackendURL(r)
	backendSubprotocols := websocketSubprotocols(r)
	dialHeaders := c.buildBackendDialHeaders(r)

	dialer := *c.dialer
	dialer.Subprotocols = backendSubprotocols
	backendConn, resp, err := dialer.DialContext(r.Context(), backendURL, dialHeaders)
	if err != nil {
		slog.Error("websocket rfc8441: failed to connect to backend", "url", backendURL, "error", err)
		if resp != nil {
			slog.Debug("websocket rfc8441: backend response", "status", resp.Status)
		}
		http.Error(w, "Failed to connect to backend", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	if selected := backendConn.Subprotocol(); selected != "" {
		w.Header().Set("Sec-WebSocket-Protocol", selected)
	}

	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	clientConn := &websocketStreamConn{body: r.Body, writer: w, controller: rc}
	defer clientConn.Close()

	session := c.newSessionState(r, origin, backendURL)

	// Emit connection opened event.
	emitWebSocketConnectionLifecycle(r.Context(), c.cfg, r, session.connectionID, session.provider, "opened", 0)
	defer func() {
		duration := time.Since(startTime).Seconds()
		metric.WebSocketConnectionDuration(origin, duration)
		emitWebSocketConnectionLifecycle(r.Context(), c.cfg, r, session.connectionID, session.provider, "closed", duration)
	}()

	needsFrameRelay := c.budgetEnforcer != nil || c.buildMessageHandler() != nil

	if needsFrameRelay {
		c.rfc8441FrameRelay(r.Context(), session, backendConn, clientConn)
	} else {
		c.rfc8441RawRelay(backendConn, clientConn)
	}
}

// rfc8441RawRelay performs a fast raw byte passthrough when no policies or
// budgets are configured. It still emits basic connection-level metrics.
func (c *WebSocketAction) rfc8441RawRelay(backendConn *websocket.Conn, clientConn *websocketStreamConn) {
	rawBackend := backendConn.NetConn()
	if c.MaxFrameSize > 0 {
		_ = rawBackend.SetReadDeadline(time.Time{})
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		proxyRawWebSocketStream(clientConn, rawBackend)
	}()
	go func() {
		defer wg.Done()
		proxyRawWebSocketStream(rawBackend, clientConn)
	}()
	wg.Wait()
}

// rfc8441FrameRelay performs frame-level proxying through the same
// processMessage/observeMessage pipeline used by the classic WebSocket path.
// The backend side uses gorilla's ReadMessage/WriteMessage. The client side
// uses manual WebSocket frame encoding/decoding over the raw HTTP/2 stream.
func (c *WebSocketAction) rfc8441FrameRelay(
	ctx context.Context,
	session *websocketSessionState,
	backendConn *websocket.Conn,
	clientConn *websocketStreamConn,
) {
	if c.MaxFrameSize > 0 {
		backendConn.SetReadLimit(int64(c.MaxFrameSize))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg        sync.WaitGroup
		closeOnce sync.Once
	)
	wg.Add(2)

	// Client -> Backend: read WebSocket frames from the raw HTTP/2 stream,
	// run through processMessage, then write to backend via gorilla.
	go func() {
		defer wg.Done()
		c.rfc8441RelayClientToBackend(ctx, cancel, &closeOnce, session, clientConn, backendConn)
	}()

	// Backend -> Client: read frames from backend via gorilla,
	// run through processMessage, then write WebSocket frames to the raw stream.
	go func() {
		defer wg.Done()
		c.rfc8441RelayBackendToClient(ctx, cancel, &closeOnce, session, backendConn, clientConn)
	}()

	wg.Wait()
}

func (c *WebSocketAction) rfc8441RelayClientToBackend(
	ctx context.Context,
	cancel context.CancelFunc,
	closeOnce *sync.Once,
	session *websocketSessionState,
	clientConn *websocketStreamConn,
	backendConn *websocket.Conn,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		messageType, payload, err := readWebSocketFrame(clientConn)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Debug("websocket rfc8441: client read error", "error", err)
			}
			cancel()
			return
		}

		// Handle control frames directly.
		if messageType == websocket.CloseMessage {
			// Forward close to backend and stop.
			deadline := time.Now().Add(5 * time.Second)
			_ = backendConn.WriteControl(websocket.CloseMessage, payload, deadline)
			cancel()
			return
		}
		if messageType == websocket.PingMessage {
			// Reply with pong to client, forward ping to backend.
			_ = writeWebSocketFrame(clientConn, websocket.PongMessage, payload)
			continue
		}
		if messageType == websocket.PongMessage {
			continue
		}

		msg := &MessageContext{
			Protocol:     MessageProtocolWebSocket,
			Phase:        MessagePhaseMessage,
			Direction:    MessageDirectionClientToBackend,
			MessageType:  messageType,
			Path:         session.request.URL.Path,
			Headers:      session.request.Header.Clone(),
			Payload:      payload,
			ConnectionID: session.connectionID,
			Provider:     session.provider,
			Request:      session.request,
			Metadata: map[string]any{
				"origin": session.origin,
			},
		}

		if err := c.processMessage(ctx, session, msg); err != nil {
			closeOnce.Do(func() {
				c.rfc8441CloseOnError(backendConn, clientConn, err)
				cancel()
			})
			return
		}

		if err := backendConn.WriteMessage(msg.MessageType, msg.Payload); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Error("websocket rfc8441: backend write error", "error", err)
			}
			cancel()
			return
		}

		metric.WebSocketFrameRelayed(session.origin, MessageDirectionClientToBackend, session.provider)
		metric.WebSocketBytesTransferred(session.origin, MessageDirectionClientToBackend, session.provider, len(msg.Payload))
	}
}

func (c *WebSocketAction) rfc8441RelayBackendToClient(
	ctx context.Context,
	cancel context.CancelFunc,
	closeOnce *sync.Once,
	session *websocketSessionState,
	backendConn *websocket.Conn,
	clientConn *websocketStreamConn,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		messageType, payload, err := backendConn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Debug("websocket rfc8441: backend read error", "error", err)
			}
			cancel()
			return
		}

		msg := &MessageContext{
			Protocol:     MessageProtocolWebSocket,
			Phase:        MessagePhaseMessage,
			Direction:    MessageDirectionBackendToClient,
			MessageType:  messageType,
			Path:         session.request.URL.Path,
			Headers:      session.request.Header.Clone(),
			Payload:      payload,
			ConnectionID: session.connectionID,
			Provider:     session.provider,
			Request:      session.request,
			Metadata: map[string]any{
				"origin": session.origin,
			},
		}

		if err := c.processMessage(ctx, session, msg); err != nil {
			closeOnce.Do(func() {
				c.rfc8441CloseOnError(backendConn, clientConn, err)
				cancel()
			})
			return
		}

		if err := writeWebSocketFrame(clientConn, msg.MessageType, msg.Payload); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Error("websocket rfc8441: client write error", "error", err)
			}
			cancel()
			return
		}

		metric.WebSocketFrameRelayed(session.origin, MessageDirectionBackendToClient, session.provider)
		metric.WebSocketBytesTransferred(session.origin, MessageDirectionBackendToClient, session.provider, len(msg.Payload))
	}
}

// rfc8441CloseOnError sends a close frame to both sides when a processMessage
// error (e.g., budget exceeded or policy violation) terminates the session.
func (c *WebSocketAction) rfc8441CloseOnError(backendConn *websocket.Conn, clientConn *websocketStreamConn, err error) {
	code := websocket.CloseInternalServerErr
	reason := "internal error"

	if closeErr, ok := websocketCloseError(err); ok {
		code = closeErr.Code
		if closeErr.Reason != "" {
			reason = closeErr.Reason
		}
	}

	closePayload := websocket.FormatCloseMessage(code, reason)
	deadline := time.Now().Add(5 * time.Second)
	_ = backendConn.WriteControl(websocket.CloseMessage, closePayload, deadline)
	// Write a close frame to the raw client stream.
	_ = writeWebSocketFrame(clientConn, websocket.CloseMessage, closePayload)
}

// ---------------------------------------------------------------------------
// WebSocket frame codec for raw HTTP/2 streams (RFC 6455 Section 5.2)
// ---------------------------------------------------------------------------

// readWebSocketFrame reads a single WebSocket frame from a raw stream.
// Client-to-server frames are masked per RFC 6455. This function unmasks
// the payload before returning it.
func readWebSocketFrame(r io.Reader) (messageType int, payload []byte, err error) {
	// Read first two bytes: FIN + opcode, MASK + payload length.
	var header [2]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}

	// FIN bit is header[0] & 0x80; we don't need to reassemble fragments for
	// the message types we care about (text, binary, close, ping, pong) since
	// gorilla also doesn't expose fragmentation to callers.
	opcode := int(header[0] & 0x0F)
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}

	if masked {
		maskBytes(maskKey, payload)
	}

	return opcode, payload, nil
}

// writeWebSocketFrame writes a single unmasked WebSocket frame to a raw stream.
// Server-to-client frames must not be masked per RFC 6455.
func writeWebSocketFrame(w io.Writer, messageType int, payload []byte) error {
	length := len(payload)

	// Calculate header size: 2 bytes base + 0/2/8 for extended length.
	var headerSize int
	switch {
	case length <= 125:
		headerSize = 2
	case length <= 65535:
		headerSize = 4
	default:
		headerSize = 10
	}

	header := make([]byte, headerSize)

	// FIN bit set, opcode in lower 4 bits.
	header[0] = 0x80 | byte(messageType&0x0F)

	// No mask bit (server-to-client).
	switch {
	case length <= 125:
		header[1] = byte(length)
	case length <= 65535:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(length))
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(length))
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	if length > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// maskBytes applies the XOR mask in-place per RFC 6455 Section 5.3.
func maskBytes(key [4]byte, data []byte) {
	for i := range data {
		data[i] ^= key[i%4]
	}
}

// ---------------------------------------------------------------------------
// Raw passthrough helpers (unchanged)
// ---------------------------------------------------------------------------

func proxyRawWebSocketStream(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
	_, _ = io.Copy(dst, src)
	closeWebSocketWrite(dst)
}

func closeWebSocketWrite(v any) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := v.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// ---------------------------------------------------------------------------
// websocketStreamConn wraps an HTTP/2 stream as a net.Conn for raw relay
// ---------------------------------------------------------------------------

type websocketStreamConn struct {
	body       io.ReadCloser
	writer     http.ResponseWriter
	controller *http.ResponseController
}

func (c *websocketStreamConn) Read(p []byte) (int, error) { return c.body.Read(p) }

func (c *websocketStreamConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if err == nil && c.controller != nil {
		_ = c.controller.Flush()
	}
	return n, err
}

func (c *websocketStreamConn) Close() error {
	if c.body != nil {
		return c.body.Close()
	}
	return nil
}

func (c *websocketStreamConn) CloseRead() error  { return nil }
func (c *websocketStreamConn) CloseWrite() error { return nil }

func (c *websocketStreamConn) LocalAddr() net.Addr  { return websocketStreamAddr("rfc8441-local") }
func (c *websocketStreamConn) RemoteAddr() net.Addr { return websocketStreamAddr("rfc8441-remote") }

func (c *websocketStreamConn) SetDeadline(time.Time) error      { return nil }
func (c *websocketStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *websocketStreamConn) SetWriteDeadline(time.Time) error { return nil }

type websocketStreamAddr string

func (a websocketStreamAddr) Network() string { return "websocket-stream" }
func (a websocketStreamAddr) String() string  { return string(a) }

// Ensure websocketStreamConn satisfies the required interfaces.
var (
	_ io.ReadWriteCloser = (*websocketStreamConn)(nil)
	_ net.Conn           = (*websocketStreamConn)(nil)
	_ fmt.Stringer       = websocketStreamAddr("")
)

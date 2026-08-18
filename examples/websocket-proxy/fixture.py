#!/usr/bin/env python3
"""Local WebSocket upstream for the websocket-proxy example.

Speaks the minimum of RFC 6455 needed to demonstrate the proxy's
transparent upgrade: computes Sec-WebSocket-Accept from the client's
Sec-WebSocket-Key, replies 101 Switching Protocols, then echoes back
every text frame it receives, prefixed with "echo: ", until the client
closes the connection.

A request that does not carry the Upgrade: websocket header gets a
plain 400 - this fixture only speaks the handshake, not general HTTP.
That is deliberate: the gateway forwards a non-upgrade request to this
same origin unchanged, so this fixture's response is exactly what a
client sees when it points a plain HTTP call at a websocket action.

Stdlib only, no dependencies:

    python3 fixture.py [port]

Defaults to port 8100, matching the example's sb.yml.
"""

import base64
import hashlib
import socket
import sys

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_key(client_key: str) -> str:
    digest = hashlib.sha1((client_key + GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def read_request_headers(conn: socket.socket) -> dict[str, str]:
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 16384:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0]
    lines = head.decode("latin-1").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def decode_frame(conn: socket.socket):
    header = conn.recv(2)
    if len(header) < 2:
        return None
    opcode = header[0] & 0x0F
    masked = header[1] & 0x80
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(conn.recv(2), "big")
    elif length == 127:
        length = int.from_bytes(conn.recv(8), "big")
    mask = conn.recv(4) if masked else b""
    payload = b""
    while len(payload) < length:
        chunk = conn.recv(length - len(payload))
        if not chunk:
            break
        payload += chunk
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def encode_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([length])
    elif length < 65536:
        header += bytes([126]) + length.to_bytes(2, "big")
    else:
        header += bytes([127]) + length.to_bytes(8, "big")
    return header + payload


def serve_one(conn: socket.socket) -> None:
    headers = read_request_headers(conn)
    if headers.get("upgrade", "").lower() != "websocket" or "sec-websocket-key" not in headers:
        body = b"this fixture only speaks the WebSocket upgrade handshake\n"
        conn.sendall(
            b"HTTP/1.1 400 Bad Request\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        return
    accept = accept_key(headers["sec-websocket-key"])
    conn.sendall(
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n"
    )
    while True:
        frame = decode_frame(conn)
        if frame is None:
            break
        opcode, payload = frame
        if opcode == 0x8:  # close
            conn.sendall(encode_frame(b"", opcode=0x8))
            break
        if opcode == 0x1:  # text
            conn.sendall(encode_frame(b"echo: " + payload, opcode=0x1))


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8100
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(5)
    print(f"websocket fixture listening on 127.0.0.1:{port}", file=sys.stderr)
    while True:
        conn, _addr = listener.accept()
        try:
            serve_one(conn)
        except (ConnectionError, OSError):
            pass
        finally:
            conn.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Minimal stdlib WebSocket client for the websocket-proxy example.

Connects to the proxy (127.0.0.1:8080), sends the Host header and
bearer token that select and authorize the `ws.local` origin, performs
the RFC 6455 handshake, sends one text frame, prints the echoed reply,
then closes.

Stdlib only, no dependencies:

    python3 client.py [message] [--no-token]
"""

import base64
import os
import socket
import sys

PROXY_ADDR = ("127.0.0.1", 8080)
UPGRADE_HOST = "ws.local"
TOKEN = "svc-token-alpha"


def encode_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    mask = os.urandom(4)
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([0x80 | length])
    elif length < 65536:
        header += bytes([0x80 | 126]) + length.to_bytes(2, "big")
    else:
        header += bytes([0x80 | 127]) + length.to_bytes(8, "big")
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return header + mask + masked


def recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly `count` bytes, looping over recv() as needed.

    A single recv() call is not guaranteed to return everything
    requested, especially for a payload larger than one TCP segment.
    """
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def decode_frame(sock: socket.socket) -> bytes:
    """Read one WebSocket frame and return its payload.

    Handles the 7-bit, 16-bit (126), and 64-bit (127) length encodings
    from RFC 6455 6.2, unlike a raw `header[1] & 0x7F` read, which
    treats 126/127 as if they were the literal payload length and
    misreads any frame whose payload is 126 bytes or larger.
    """
    header = recv_exact(sock, 2)
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(sock, 8), "big")
    masked = header[1] & 0x80
    mask = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return payload


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--no-token"]
    send_token = "--no-token" not in sys.argv
    message = args[0] if args else "hello through the gateway"

    key = base64.b64encode(os.urandom(16)).decode()
    auth_line = f"Authorization: Bearer {TOKEN}\r\n" if send_token else ""
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {UPGRADE_HOST}\r\n"
        f"{auth_line}"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()

    with socket.create_connection(PROXY_ADDR, timeout=5) as sock:
        sock.sendall(request)
        response = sock.recv(4096)
        head = response.decode("latin-1").split("\r\n\r\n")[0]
        print(head)
        status_line = head.split("\r\n", 1)[0]
        if " 101 " not in status_line:
            return
        print()
        sock.sendall(encode_frame(message.encode()))
        payload = decode_frame(sock)
        text = payload.decode(errors="replace")
        if len(payload) > 200:
            # A frame this size is unreadable dumped whole; show enough to
            # confirm the round trip (the fixture's "echo: " prefix, the
            # byte count, and both ends of the payload) instead.
            print(
                f"received: {len(payload)} bytes, starts {text[:30]!r}, "
                f"ends {text[-30:]!r}"
            )
        else:
            print(f"received: {text}")
        sock.sendall(encode_frame(b"", opcode=0x8))


if __name__ == "__main__":
    main()

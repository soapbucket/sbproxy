#!/usr/bin/env python3
"""Bounded local fixtures for the settlement-gate-local example.

Two servers, no network, no payment provider, no wallet:

  * a stub Core Lightning node on a Unix socket, speaking the
    newline-delimited JSON-RPC 2.0 framing the CLN adapter speaks. It
    answers the three methods the settlement path uses (`getinfo`,
    `invoice`, `listinvoices`) and nothing else.
  * a counting HTTP origin on 127.0.0.1:18080. It reports how many
    times it has actually served the article, which is the observable
    that proves one settled payment serves the content exactly once.

Lightning is the one rail that can run hermetically: CLN is not an HTTP
endpoint, it is a Unix socket, so a stub needs no TLS, no certificate,
and no reachable host. The x402, Stripe, and LND rails all require an
HTTPS endpoint this fixture cannot stand in for.

The fixture also writes the two secret files the config names, because
both are per-run values that must never be vendored: a fresh 32-byte
challenge binding key and a throwaway rune. The stub node never checks
the rune; it only has to exist.

Control endpoints on the origin, which stand in for actions a Lightning
payer and an operator take out of band:

    POST /__pay     mark the outstanding invoice paid
    POST /__reset   forget the invoice and zero the hit counter
    GET  /__hits    read the hit counter without incrementing it
"""

import json
import os
import secrets
import socket
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ORIGIN_PORT = 18080
STATE_DIR = os.environ.get("SBPROXY_SETTLEMENT_DIR", "/tmp/sbproxy-settlement")
SOCKET_PATH = os.path.join(STATE_DIR, "lightning-rpc")
BINDING_KEY_PATH = os.path.join(STATE_DIR, "binding.key")
RUNE_PATH = os.path.join(STATE_DIR, "cln.rune")

MAX_LINE_BYTES = 64 * 1024
SAFE_LOG_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)

# A syntactically valid regtest BOLT 11 prefix. The adapter checks the
# prefix and the character set, never the signature.
BOLT11_PREFIX = "lnbcrt100u1stubinvoice"


def mint_payment_hash():
    """A fresh payment hash per invoice, as 64 lowercase hex characters.

    A real node never reuses one, and neither can this stub: the
    settlement store holds a unique index on a receipt's provider
    reference, which is what stops one provider payment being credited
    as two settlements. A constant hash here therefore settled once and
    then failed every later settlement in the same state file with an
    internal error, stranding the intent in `needs_reconciliation`
    forever. It looked like a proxy bug and was this fixture standing in
    for a node badly. Every e2e test starts a fresh store and settles
    once, so nothing caught it.
    """
    return secrets.token_bytes(32).hex()

# The version the adapter probes for at startup. Below the configured
# `minimum_version` the proxy refuses to serve the rail.
NODE_VERSION = "v26.06"


def safe_log_value(value, max_length):
    """Return one bounded log field with no control or separator characters."""
    text = str(value)
    return "".join(
        character if character in SAFE_LOG_CHARACTERS else "_" for character in text
    )[:max_length]


class NodeState:
    """What the stub node knows about its one invoice, plus origin hits."""

    def __init__(self):
        self.lock = threading.Lock()
        self.label = None
        self.amount_msat = None
        self.paid = False
        self.hits = 0
        self.payment_hash = None
        self.bolt11 = None

    def record_invoice(self, label, amount_msat):
        with self.lock:
            self.label = label
            self.amount_msat = amount_msat
            self.paid = False
            self.payment_hash = mint_payment_hash()
            self.bolt11 = f"{BOLT11_PREFIX}{self.payment_hash}"
            return self.payment_hash, self.bolt11

    def mark_paid(self):
        with self.lock:
            self.paid = True

    def reset(self):
        with self.lock:
            self.label = None
            self.amount_msat = None
            self.paid = False
            self.hits = 0
            self.payment_hash = None
            self.bolt11 = None

    def snapshot(self):
        with self.lock:
            return (
                self.label,
                self.amount_msat,
                self.paid,
                self.payment_hash,
                self.bolt11,
            )

    def count_hit(self):
        with self.lock:
            self.hits += 1
            return self.hits

    def read_hits(self):
        with self.lock:
            return self.hits


STATE = NodeState()


def rpc_response(state, method, params):
    """Answer one JSON-RPC method from the stub node's state."""
    if method == "getinfo":
        # Startup probes the live version before registering the rail.
        return {"version": NODE_VERSION}

    if method == "invoice":
        label = params.get("label")
        amount_msat = params.get("amount_msat")
        payment_hash, bolt11 = state.record_invoice(label, amount_msat)
        print(
            f"cln method=invoice label={safe_log_value(label, 80)} "
            f"amount_msat={safe_log_value(amount_msat, 24)} "
            f"payment_hash={safe_log_value(payment_hash, 64)}",
            flush=True,
        )
        return {"payment_hash": payment_hash, "bolt11": bolt11}

    if method == "listinvoices":
        requested = params.get("label", "")
        label, amount_msat, paid, payment_hash, bolt11 = state.snapshot()
        if label != requested:
            return {"invoices": []}
        amount = amount_msat or 0
        print(
            f"cln method=listinvoices label={safe_log_value(requested, 80)} "
            f"status={'paid' if paid else 'unpaid'}",
            flush=True,
        )
        return {
            "invoices": [
                {
                    "label": requested,
                    "status": "paid" if paid else "unpaid",
                    "payment_hash": payment_hash,
                    "amount_msat": amount,
                    "amount_received_msat": amount if paid else 0,
                    "bolt11": bolt11,
                }
            ]
        }

    return {}


def read_line(connection):
    """Read one newline-terminated request, bounded."""
    chunks = []
    total = 0
    while total < MAX_LINE_BYTES:
        byte = connection.recv(1)
        if not byte or byte == b"\n":
            break
        chunks.append(byte)
        total += 1
    return b"".join(chunks)


def serve_cln(listener):
    """One newline-delimited JSON-RPC exchange per connection."""
    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(2)
            try:
                raw = read_line(connection)
                request = json.loads(raw)
            except (OSError, ValueError):
                continue
            result = rpc_response(
                STATE,
                request.get("method", ""),
                request.get("params") or {},
            )
            body = json.dumps(
                {"jsonrpc": "2.0", "id": request.get("id"), "result": result},
                separators=(",", ":"),
            )
            try:
                connection.sendall(body.encode() + b"\n")
            except OSError:
                continue


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def send_json(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self.send_json(200, {"status": "ok"})
            return
        if self.path == "/__hits":
            self.send_json(200, {"hits": STATE.read_hits()})
            return
        hits = STATE.count_hit()
        print(
            f"origin method=GET path={safe_log_value(self.path, 80)} hits={hits}",
            flush=True,
        )
        body = b"<h1>paid article</h1>\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/__pay":
            STATE.mark_paid()
            print("payer action=pay", flush=True)
            self.send_json(200, {"paid": True})
            return
        if self.path == "/__reset":
            STATE.reset()
            print("payer action=reset", flush=True)
            self.send_json(200, {"hits": 0, "paid": False})
            return
        self.send_json(404, {"error": "not found"})


def write_secret_file(path, value):
    """Write one demo-only secret, owner read/write only."""
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(value)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def prepare_state_dir():
    """Create the shared directory and the two per-run secret files."""
    os.makedirs(STATE_DIR, exist_ok=True)
    # A fresh binding key per run: it derives real signing material for
    # the quote token, so it is generated and never vendored.
    write_secret_file(BINDING_KEY_PATH, secrets.token_hex(32))
    # The stub node never checks the rune. Its value only has to exist.
    write_secret_file(RUNE_PATH, "settlement-gate-local-demo-rune")
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)


def serve():
    prepare_state_dir()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(SOCKET_PATH)
    listener.listen(16)
    threading.Thread(target=serve_cln, args=(listener,), daemon=True).start()

    origin = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), OriginHandler)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    print(
        f"fixture ready socket={safe_log_value(SOCKET_PATH, 120)} "
        f"origin=127.0.0.1:{ORIGIN_PORT}",
        flush=True,
    )


def self_test():
    assert safe_log_value("lightning-rpc", 80) == "lightning-rpc"
    assert safe_log_value("safe\nforged\tline\x1b", 80) == "safe_forged_line_"
    assert safe_log_value("x" * 81, 80) == "x" * 80

    state = NodeState()
    assert rpc_response(state, "getinfo", {}) == {"version": NODE_VERSION}
    invoice = rpc_response(state, "invoice", {"label": "abc", "amount_msat": 1000})
    assert invoice["bolt11"].startswith(BOLT11_PREFIX)
    assert len(invoice["payment_hash"]) == 64
    assert set(invoice["payment_hash"]) <= set("0123456789abcdef")

    # Two invoices must never share a payment hash. The settlement store
    # keys a receipt's provider reference uniquely, so a repeat would
    # settle once and then strand every later intent.
    second = rpc_response(state, "invoice", {"label": "def", "amount_msat": 1000})
    assert second["payment_hash"] != invoice["payment_hash"]
    assert second["bolt11"] != invoice["bolt11"]
    # Re-record the label the rest of this self-test reads.
    invoice = rpc_response(state, "invoice", {"label": "abc", "amount_msat": 1000})
    unknown = rpc_response(state, "listinvoices", {"label": "other"})
    assert unknown == {"invoices": []}
    unpaid = rpc_response(state, "listinvoices", {"label": "abc"})
    assert unpaid["invoices"][0]["status"] == "unpaid"
    assert unpaid["invoices"][0]["amount_received_msat"] == 0
    state.mark_paid()
    paid = rpc_response(state, "listinvoices", {"label": "abc"})
    assert paid["invoices"][0]["status"] == "paid"
    assert paid["invoices"][0]["amount_received_msat"] == 1000
    assert rpc_response(state, "unknown-method", {}) == {}
    print("fixture self-test: passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        serve()
        threading.Event().wait()

#!/usr/bin/env python3
"""Mint a sample CAP token signed with the bundled TEST private key.

Usage:
    python3 examples/auth-cap/mint.py [--aud HOST] [--sub AGENT_ID]
                                         [--glob /blog/**] [--rps 2.0]
                                         [--bytes 10737418240] [--ttl 3600]

The default claims are tuned to match the verifier configured in
`sb.yml` and the smoke.json `valid` case:

    iss   issuer.example.com
    sub   agent_acme_001
    aud   cap.localhost
    glob  /blog/**
    rps   2.0
    bytes 10 GiB / day
    ttl   3600s (exp = now + ttl)

The script implements the JWT compact-serialisation by hand using the
`cryptography` library so it has only one dependency. If `cryptography`
is not installed, run:

    python3 -m pip install cryptography

WARNING: tokens/test-private.pem is a TEST key checked into the repo.
Never reuse it in production. Mint production tokens with a key held
in your KMS / HSM and publish the matching public key via JWKS.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.stderr.write(
        "error: this script needs the `cryptography` package.\n"
        "       install it with `python3 -m pip install cryptography`.\n"
    )
    sys.exit(2)


KID = "cap-2026-q2-001"
HERE = Path(__file__).resolve().parent
DEFAULT_KEY = HERE / "tokens" / "test-private.pem"


def b64url(raw: bytes) -> str:
    """Base64url encode without padding, per RFC 7515."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    pem = path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} is not an Ed25519 private key")
    return key


def mint(
    signing: Ed25519PrivateKey,
    *,
    iss: str,
    sub: str,
    aud: str,
    glob: str,
    rps: float,
    bytes_per_day: int,
    ttl: int,
    jti: str,
) -> str:
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "cap+jwt", "kid": KID}
    claims = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "cap_v": 1,
        "rps": rps,
        "bytes": bytes_per_day,
        "glob": glob,
        "iat": now,
        "exp": now + ttl,
        "jti": jti,
    }
    header_b = b64url(json.dumps(header, separators=(",", ":")).encode())
    claims_b = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b}.{claims_b}".encode()
    sig = signing.sign(signing_input)
    return f"{header_b}.{claims_b}.{b64url(sig)}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--key", type=Path, default=DEFAULT_KEY,
                    help=f"PEM file with the Ed25519 signing key (default: {DEFAULT_KEY})")
    ap.add_argument("--iss", default="issuer.example.com")
    ap.add_argument("--sub", default="agent_acme_001")
    ap.add_argument("--aud", default="cap.localhost")
    ap.add_argument("--glob", default="/blog/**")
    ap.add_argument("--rps", type=float, default=2.0)
    ap.add_argument("--bytes", dest="bytes_per_day",
                    type=int, default=10_737_418_240,
                    help="bytes-per-day budget (default: 10 GiB)")
    ap.add_argument("--ttl", type=int, default=3600,
                    help="lifetime in seconds; exp = now + ttl (default: 3600)")
    ap.add_argument("--jti", default="01J7HZ8X9R3CAPSAMPL",
                    help="token id (used as the rate-limit bucket key)")
    args = ap.parse_args()

    signing = load_signing_key(args.key)
    token = mint(
        signing,
        iss=args.iss,
        sub=args.sub,
        aud=args.aud,
        glob=args.glob,
        rps=args.rps,
        bytes_per_day=args.bytes_per_day,
        ttl=args.ttl,
        jti=args.jti,
    )
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())

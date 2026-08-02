#!/usr/bin/env python3
"""Verify an SBproxy receipt chain with nothing but the published JWKS.

This is the buyer's side of attested metering. It has no SBproxy code in
it: everything below re-derives what the proxy wrote, from the file and
the public key set alone, so a disagreement it finds is a disagreement
anyone can reproduce.

Per entry it checks four things, in order:

  1. `seq` runs from 0 with no gaps, so nothing was removed.
  2. `prev_hash` equals the previous entry's `entry_hash`, so nothing
     was reordered or spliced.
  3. `entry_hash` equals SHA-256 over `prev_hash`, `seq` (8 raw
     little-endian bytes), `recorded_at`, and the receipt's own bytes,
     each of the first three followed by a newline. A change to any
     field of any past receipt fails here.
  4. The Ed25519 `signature` over that raw 32-byte digest verifies
     against the JWKS key, so the record is attributable to the holder
     of the published key and cannot be quietly re-written and
     re-signed by anyone else.

The receipt bytes are taken verbatim from the line, never re-serialized:
re-encoding JSON can change bytes the digest covers, and the point of
the exercise is to check the bytes that were signed.

Usage:
  # Fetch the key set the operator publishes:
  curl -s -H 'Host: api.local' \
    http://127.0.0.1:8080/.well-known/http-message-signatures-directory \
    > jwks.json

  # Verify a chain file (or an export of one):
  ./bin/verify-chain.py --chain /tmp/sbproxy-metering/receipts.ndjson \
    --jwks jwks.json

Exit code 0 when every link and signature checks out, 1 otherwise.
Requires the `cryptography` package: pip install cryptography
"""

import argparse
import base64
import hashlib
import json
import struct
import sys

GENESIS = "0" * 64
EVENT_MARKER = '"event":'


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def fail(seq, reason):
    print(f"chain verify: FAILED at seq {seq}: {reason}")
    sys.exit(1)


def pick_key(jwks_path, kid):
    with open(jwks_path, encoding="utf-8") as handle:
        document = json.load(handle)
    keys = {
        key["kid"]: key
        for key in document.get("keys", [])
        if key.get("kty") == "OKP" and key.get("crv") == "Ed25519" and "kid" in key
    }
    if not keys:
        sys.exit(f"{jwks_path} holds no Ed25519 keys")
    if kid is not None:
        if kid not in keys:
            sys.exit(f"kid `{kid}` is not in {jwks_path} (available: {', '.join(sorted(keys))})")
        return keys[kid]
    if len(keys) == 1:
        return next(iter(keys.values()))
    sys.exit(f"{jwks_path} holds {len(keys)} keys; pick one with --kid ({', '.join(sorted(keys))})")


def main():
    parser = argparse.ArgumentParser(
        description="Verify an SBproxy receipt chain against a published JWKS."
    )
    parser.add_argument("--chain", required=True, help="receipt chain file (JSONL)")
    parser.add_argument("--jwks", required=True, help="JWKS file fetched from the operator")
    parser.add_argument("--kid", help="key id to verify with, when the JWKS holds several")
    args = parser.parse_args()

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        sys.exit("this script needs the `cryptography` package: pip install cryptography")

    jwk = pick_key(args.jwks, args.kid)
    public_key = Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))

    expected_seq = 0
    head = GENESIS
    with open(args.chain, encoding="utf-8") as chain:
        for raw in chain:
            line = raw.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                fail(expected_seq, f"unparseable entry: {error}")

            seq = entry.get("seq")
            if seq != expected_seq:
                fail(seq, f"out-of-order seq: expected {expected_seq}, found {seq}")
            if entry.get("prev_hash") != head:
                fail(seq, "prev_hash does not match the running chain head")

            # The receipt's bytes, exactly as written. `event` is the last
            # field of every entry, so everything between the marker and
            # the line's closing brace is the payload the digest covers.
            at = line.find(EVENT_MARKER)
            if at < 0:
                fail(seq, "entry has no event field")
            event_bytes = line[at + len(EVENT_MARKER):-1].encode("utf-8")

            digest = hashlib.sha256()
            digest.update(entry["prev_hash"].encode("ascii"))
            digest.update(b"\n")
            digest.update(struct.pack("<Q", seq))
            digest.update(b"\n")
            digest.update(entry["recorded_at"].encode("utf-8"))
            digest.update(b"\n")
            digest.update(event_bytes)
            raw_digest = digest.digest()

            if raw_digest.hex() != entry.get("entry_hash"):
                fail(seq, "entry_hash does not match recomputed digest (tampered event)")

            signature = entry.get("signature")
            if signature is None:
                fail(seq, "expected a signature but entry is unsigned")
            try:
                public_key.verify(bytes.fromhex(signature), raw_digest)
            except (ValueError, InvalidSignature):
                fail(seq, "signature does not verify against the published key")

            head = entry["entry_hash"]
            expected_seq += 1

    plural = "y" if expected_seq == 1 else "ies"
    print(
        f"chain verify: OK ({expected_seq} entr{plural}, "
        f"chain + signatures against kid {jwk['kid']})"
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Soap Bucket LLC
#
# sign-x402.sh
#
# Turn a 402's PAYMENT-REQUIRED header into the PAYMENT-SIGNATURE header
# value the proxy accepts on the retry.
#
# The x402 v2 credential is not a JSON request body. It is one
# PAYMENT-SIGNATURE header carrying standard base64 of a PaymentPayload
# envelope, and the envelope has to echo the challenge exactly:
#
#   {
#     "x402Version": 2,
#     "resource":   <exact echo of the challenge's resource>,
#     "accepted":   <exact echo of the accepts entry you chose>,
#     "payload":    <the scheme's signed object>,
#     "extensions": <exact echo of the challenge's extensions>
#   }
#
# The proxy compares those echoes byte for byte before it contacts a
# facilitator, so this script copies them out of the challenge rather than
# reconstructing them. Only `payload` is built here: an EIP-3009
# transferWithAuthorization signed with your key, which is what the
# facilitator verifies.
#
# Required tools: cast (foundry), jq, base64.
#
# Required arguments:
#   --challenge <b64>     The PAYMENT-REQUIRED header value from the 402.
#   --private-key <hex>   Payer's private key, 0x-prefixed.
#
# Optional arguments:
#   --index <n>           Which `accepts` entry to pay. Default: 0.
#   --valid-after <int>   Unix time the authorization becomes valid.
#                         Default: now.
#   --valid-before <int>  Unix time it expires. Default: now + 600.
#   --nonce <hex>         Per-authorization nonce. Default: random.
#   --rpc-url <url>       RPC endpoint used to read the token's name and
#                         version for the EIP-712 domain.
#                         Default: https://sepolia.base.org.
#
# Output: the PAYMENT-SIGNATURE value on stdout, with no trailing newline
# inside the value itself.
#
# Example:
#
#   CHALLENGE=$(curl -sD - -o /dev/null \
#     -H 'Host: blog.test.sbproxy.dev' \
#     -H 'User-Agent: GPTBot/1.0' \
#     -H 'Accept-Payment: x402' \
#     http://127.0.0.1:8080/article \
#     | awk -F': ' 'tolower($1)=="payment-required"{print $2}' | tr -d '\r')
#
#   SIGNATURE=$(./bin/sign-x402.sh --challenge "$CHALLENGE" \
#                 --private-key "$X402_PRIVATE_KEY")
#
#   curl -i -H 'Host: blog.test.sbproxy.dev' \
#        -H 'User-Agent: GPTBot/1.0' \
#        -H "PAYMENT-SIGNATURE: $SIGNATURE" \
#        http://127.0.0.1:8080/article

set -euo pipefail

CHALLENGE=""
PRIVATE_KEY=""
INDEX=0
VALID_AFTER=""
VALID_BEFORE=""
NONCE=""
RPC_URL="https://sepolia.base.org"

while [ $# -gt 0 ]; do
  case "$1" in
    --challenge)     CHALLENGE="$2"; shift 2 ;;
    --private-key)   PRIVATE_KEY="$2"; shift 2 ;;
    --index)         INDEX="$2"; shift 2 ;;
    --valid-after)   VALID_AFTER="$2"; shift 2 ;;
    --valid-before)  VALID_BEFORE="$2"; shift 2 ;;
    --nonce)         NONCE="$2"; shift 2 ;;
    --rpc-url)       RPC_URL="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,62p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

for var in CHALLENGE PRIVATE_KEY; do
  if [ -z "${!var}" ]; then
    echo "missing required argument: --${var,,}" >&2
    exit 2
  fi
done

for cmd in cast jq base64; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required tool not found on PATH: $cmd" >&2
    echo "install foundry (cast): https://book.getfoundry.sh/getting-started/installation" >&2
    exit 127
  fi
done

# --- Decode the challenge ---
#
# Standard RFC 4648 base64 with padding. Base64url is not accepted by the
# proxy and is not produced here.

DECODED=$(printf '%s' "$CHALLENGE" | base64 -d)

VERSION=$(printf '%s' "$DECODED" | jq -r '.x402Version')
if [ "$VERSION" != "2" ]; then
  echo "challenge is x402Version $VERSION; this script speaks version 2" >&2
  exit 3
fi

RESOURCE=$(printf '%s' "$DECODED" | jq -c '.resource')
EXTENSIONS=$(printf '%s' "$DECODED" | jq -c '.extensions')
ACCEPTED=$(printf '%s' "$DECODED" | jq -c ".accepts[$INDEX]")
if [ "$ACCEPTED" = "null" ]; then
  echo "challenge has no accepts[$INDEX] entry" >&2
  exit 3
fi

SCHEME=$(printf '%s' "$ACCEPTED" | jq -r '.scheme')
if [ "$SCHEME" != "exact" ]; then
  echo "accepts[$INDEX] uses scheme $SCHEME; this script signs the exact scheme only" >&2
  exit 3
fi

NETWORK=$(printf '%s' "$ACCEPTED" | jq -r '.network')
AMOUNT=$(printf '%s' "$ACCEPTED" | jq -r '.amount')
TOKEN=$(printf '%s' "$ACCEPTED" | jq -r '.asset')
PAY_TO=$(printf '%s' "$ACCEPTED" | jq -r '.payTo')

# CAIP-2: `namespace:reference`. For eip155 the reference is the chain id.
CAIP_NAMESPACE=${NETWORK%%:*}
CHAIN_ID=${NETWORK#*:}
if [ "$CAIP_NAMESPACE" != "eip155" ]; then
  echo "network $NETWORK is not an eip155 chain; this script signs EIP-3009 only" >&2
  exit 3
fi

# --- Defaults ---

if [ -z "$VALID_AFTER" ]; then
  VALID_AFTER=$(date +%s)
fi
if [ -z "$VALID_BEFORE" ]; then
  VALID_BEFORE=$((VALID_AFTER + 600))
fi
if [ -z "$NONCE" ]; then
  NONCE=$(cast keccak "$(date +%s%N)-$RANDOM-$RANDOM")
fi

FROM=$(cast wallet address --private-key "$PRIVATE_KEY")

# --- EIP-712 digest ---
#
# TransferWithAuthorization (EIP-3009):
#   address from, address to, uint256 value,
#   uint256 validAfter, uint256 validBefore, bytes32 nonce
#
# The domain separator uses the token's own name() and version().

TOKEN_NAME=$(cast call --rpc-url "$RPC_URL" "$TOKEN" "name()(string)")
TOKEN_VERSION=$(cast call --rpc-url "$RPC_URL" "$TOKEN" "version()(string)" 2>/dev/null || echo "2")

TOKEN_NAME=${TOKEN_NAME%\"}
TOKEN_NAME=${TOKEN_NAME#\"}
TOKEN_VERSION=${TOKEN_VERSION%\"}
TOKEN_VERSION=${TOKEN_VERSION#\"}

DOMAIN_TYPEHASH=$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
NAME_HASH=$(cast keccak "$TOKEN_NAME")
VERSION_HASH=$(cast keccak "$TOKEN_VERSION")

DOMAIN_SEPARATOR=$(cast keccak \
  "$(cast abi-encode "f(bytes32,bytes32,bytes32,uint256,address)" \
       "$DOMAIN_TYPEHASH" "$NAME_HASH" "$VERSION_HASH" "$CHAIN_ID" "$TOKEN")")

STRUCT_TYPEHASH=$(cast keccak \
  "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")

STRUCT_HASH=$(cast keccak \
  "$(cast abi-encode "f(bytes32,address,address,uint256,uint256,uint256,bytes32)" \
       "$STRUCT_TYPEHASH" "$FROM" "$PAY_TO" "$AMOUNT" "$VALID_AFTER" "$VALID_BEFORE" "$NONCE")")

DIGEST=$(cast keccak "0x1901${DOMAIN_SEPARATOR#0x}${STRUCT_HASH#0x}")

SIG=$(cast wallet sign --no-hash --private-key "$PRIVATE_KEY" "$DIGEST")
SIG_NO_PREFIX=${SIG#0x}
R="0x${SIG_NO_PREFIX:0:64}"
S="0x${SIG_NO_PREFIX:64:64}"
V_HEX="0x${SIG_NO_PREFIX:128:2}"
V=$(printf "%d" "$V_HEX")

# --- Build and encode the envelope ---
#
# resource, accepted, and extensions are echoed exactly as they arrived.
# The proxy compares them before any facilitator call, so re-serializing
# them differently is the usual reason a retry is refused locally.

PAYLOAD=$(jq -n \
  --arg from "$FROM" \
  --arg to "$PAY_TO" \
  --arg value "$AMOUNT" \
  --argjson valid_after "$VALID_AFTER" \
  --argjson valid_before "$VALID_BEFORE" \
  --arg nonce "$NONCE" \
  --argjson v "$V" \
  --arg r "$R" \
  --arg s "$S" \
  '{
    from: $from,
    to: $to,
    value: $value,
    validAfter: $valid_after,
    validBefore: $valid_before,
    nonce: $nonce,
    signature: { v: $v, r: $r, s: $s }
  }')

jq -cn \
  --argjson resource "$RESOURCE" \
  --argjson accepted "$ACCEPTED" \
  --argjson payload "$PAYLOAD" \
  --argjson extensions "$EXTENSIONS" \
  '{
    x402Version: 2,
    resource: $resource,
    accepted: $accepted,
    payload: $payload,
    extensions: $extensions
  }' | base64 | tr -d '\n'

#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Soap Bucket LLC
#
# sign-x402.sh
#
# Build an EIP-712 `transferWithAuthorization` payload for the x402
# rail, sign it with a Base Sepolia (or any EVM) testnet key, and
# print the JSON envelope the proxy expects in the redeem POST body.
#
# Wraps `cast` (foundry) so an operator does not have to remember the
# EIP-712 domain separator + struct hash math. The output is a
# pretty-printed JSON object on stdout; pipe it into curl.
#
# Required tools: cast (foundry), jq.
#
# Required arguments:
#   --pay-to <address>      Receiving address (the publisher's wallet).
#   --amount <micros>       Amount in token micros (e.g. 1000 for 1 USDC unit
#                           on a 6-decimal token). NOT USD; this is the raw
#                           on-chain unit.
#   --token <address>       ERC-20 token contract address (USDC on Base
#                           Sepolia: 0x036CbD53842c5426634e7929541eC2318f3dCF7e).
#   --private-key <hex>     Sender's private key as 0x-prefixed hex.
#
# Optional arguments:
#   --chain-id <int>        EVM chain id. Default: 84532 (Base Sepolia).
#   --valid-after <int>     Unix timestamp the authorization becomes valid.
#                           Default: now.
#   --valid-before <int>    Unix timestamp the authorization expires.
#                           Default: now + 600 (ten minutes).
#   --nonce <hex>           Per-authorization nonce. Default: random 32 bytes.
#   --rpc-url <url>         RPC endpoint for chain reads (verifying nonce
#                           is unused). Default: https://sepolia.base.org.
#
# Output: a JSON object on stdout with the payload the proxy redeem
# endpoint expects:
#
#   {
#     "rail": "x402",
#     "version": "2",
#     "chain": "base-sepolia",
#     "from": "0x...",
#     "to": "0x...",
#     "value": "1000",
#     "valid_after": 1714680000,
#     "valid_before": 1714680600,
#     "nonce": "0x...",
#     "signature": { "v": 28, "r": "0x...", "s": "0x..." }
#   }
#
# Example:
#
#   PAYLOAD=$(./bin/sign-x402.sh \
#     --pay-to "$PAY_TO" \
#     --amount 1000 \
#     --token 0x036CbD53842c5426634e7929541eC2318f3dCF7e \
#     --private-key "$X402_PRIVATE_KEY")
#
#   curl -i -H 'Host: blog.localhost' \
#        -H 'User-Agent: GPTBot/1.0' \
#        -H "crawler-payment: $TOKEN" \
#        -H 'Content-Type: application/json' \
#        --data-raw "$PAYLOAD" \
#        http://localhost:8080/articles/foo

set -euo pipefail

# --- Argument parsing ---

PAY_TO=""
AMOUNT=""
TOKEN=""
PRIVATE_KEY=""
CHAIN_ID=84532
VALID_AFTER=""
VALID_BEFORE=""
NONCE=""
RPC_URL="https://sepolia.base.org"

while [ $# -gt 0 ]; do
  case "$1" in
    --pay-to)        PAY_TO="$2"; shift 2 ;;
    --amount)        AMOUNT="$2"; shift 2 ;;
    --token)         TOKEN="$2"; shift 2 ;;
    --private-key)   PRIVATE_KEY="$2"; shift 2 ;;
    --chain-id)      CHAIN_ID="$2"; shift 2 ;;
    --valid-after)   VALID_AFTER="$2"; shift 2 ;;
    --valid-before)  VALID_BEFORE="$2"; shift 2 ;;
    --nonce)         NONCE="$2"; shift 2 ;;
    --rpc-url)       RPC_URL="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,60p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

for var in PAY_TO AMOUNT TOKEN PRIVATE_KEY; do
  if [ -z "${!var}" ]; then
    echo "missing required argument: --${var,,}" >&2
    exit 2
  fi
done

# --- Tool checks ---

for cmd in cast jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required tool not found on PATH: $cmd" >&2
    echo "install foundry (cast): https://book.getfoundry.sh/getting-started/installation" >&2
    exit 127
  fi
done

# --- Defaults ---

if [ -z "$VALID_AFTER" ]; then
  VALID_AFTER=$(date +%s)
fi
if [ -z "$VALID_BEFORE" ]; then
  VALID_BEFORE=$((VALID_AFTER + 600))
fi
if [ -z "$NONCE" ]; then
  NONCE="0x$(cast wallet new --json | jq -r '.[0].private_key' | sed 's/^0x//')"
fi

# Derive the sender address from the private key.
FROM=$(cast wallet address --private-key "$PRIVATE_KEY")

# --- EIP-712 hash construction ---
#
# TransferWithAuthorization struct (EIP-3009):
#   address from
#   address to
#   uint256 value
#   uint256 validAfter
#   uint256 validBefore
#   bytes32 nonce
#
# Domain separator uses the token's `name()` and `version()` from
# the contract. We read them via cast.

TOKEN_NAME=$(cast call --rpc-url "$RPC_URL" "$TOKEN" "name()(string)")
TOKEN_VERSION=$(cast call --rpc-url "$RPC_URL" "$TOKEN" "version()(string)" 2>/dev/null || echo "2")

# Strip the surrounding double-quotes cast adds to string returns.
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

# EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash).
DIGEST=$(cast keccak \
  "0x1901${DOMAIN_SEPARATOR#0x}${STRUCT_HASH#0x}")

# --- Sign the digest ---

SIG=$(cast wallet sign --no-hash --private-key "$PRIVATE_KEY" "$DIGEST")
# cast emits 0x-prefixed 65-byte signature: r (32) || s (32) || v (1).
SIG_NO_PREFIX=${SIG#0x}
R="0x${SIG_NO_PREFIX:0:64}"
S="0x${SIG_NO_PREFIX:64:64}"
V_HEX="0x${SIG_NO_PREFIX:128:2}"
V=$(printf "%d" "$V_HEX")

# --- Emit the payload ---

jq -n \
  --arg rail "x402" \
  --arg version "2" \
  --arg chain "base-sepolia" \
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
    rail: $rail,
    version: $version,
    chain: $chain,
    from: $from,
    to: $to,
    value: $value,
    valid_after: $valid_after,
    valid_before: $valid_before,
    nonce: $nonce,
    signature: { v: $v, r: $r, s: $s }
  }'

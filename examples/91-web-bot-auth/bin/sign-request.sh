#!/usr/bin/env bash
# Sign an HTTP request with an Ed25519 key per RFC 9421 (HTTP Message
# Signatures), the format the `bot_auth` policy verifies. Output is
# the `Signature-Input` and `Signature` header lines, ready to paste
# into curl.
#
# Usage:
#   ./bin/sign-request.sh \
#     --key      <private-key.pem> \
#     --keyid    <directory-key-id> \
#     --method   GET \
#     --target-uri http://127.0.0.1:8080/article \
#     [--authority blog.local]
#
# Generate a keypair (one-time, paired to the directory entry in sb.yml):
#   openssl genpkey -algorithm ed25519 -out openai-bot.pem
#   openssl pkey -in openai-bot.pem -pubout -outform DER | tail -c 32 | xxd -p -c 64
#   # ^ paste that hex into the matching `public_key:` field in sb.yml
#
# End-to-end smoke:
#   eval $(./bin/sign-request.sh --key openai-bot.pem --keyid openai-2026-01 \
#           --method GET --target-uri http://127.0.0.1:8080/article)
#   curl -i -H "Signature-Input: $SIG_INPUT" -H "Signature: $SIG" \
#        http://127.0.0.1:8080/article
#
# The script prints the headers as `SIG_INPUT=...` and `SIG=...` shell
# assignments so the eval form above works. Use --raw to print the
# header values bare instead.

set -euo pipefail

KEY=""
KEYID=""
METHOD=""
URI=""
AUTHORITY=""
RAW=0

while [ $# -gt 0 ]; do
  case "$1" in
    --key)         KEY="$2"; shift 2 ;;
    --keyid)       KEYID="$2"; shift 2 ;;
    --method)      METHOD="$2"; shift 2 ;;
    --target-uri)  URI="$2"; shift 2 ;;
    --authority)   AUTHORITY="$2"; shift 2 ;;
    --raw)         RAW=1; shift ;;
    -h|--help)
      sed -n '2,32p' "$0"
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
  esac
done

for var in KEY KEYID METHOD URI; do
  if [ -z "${!var}" ]; then
    echo "missing required flag: --${var,,}" >&2
    sed -n '2,32p' "$0" >&2
    exit 2
  fi
done

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found in PATH; install it and retry" >&2
  exit 2
fi
if ! command -v base64 >/dev/null 2>&1; then
  echo "base64 not found in PATH" >&2
  exit 2
fi

# Derive the @authority covered component from the URI if not given.
if [ -z "$AUTHORITY" ]; then
  AUTHORITY=$(printf "%s" "$URI" | sed -E 's#^https?://##; s#/.*##')
fi

CREATED=$(date -u +%s)
SIG_PARAMS="(\"@method\" \"@target-uri\" \"@authority\");keyid=\"$KEYID\";created=$CREATED;alg=\"ed25519\""
SIG_INPUT_LINE="sig1=$SIG_PARAMS"

# Build the signature base per RFC 9421 §2.5.
SIG_BASE=$(printf '"@method": %s\n"@target-uri": %s\n"@authority": %s\n"@signature-params": %s' \
  "$METHOD" "$URI" "$AUTHORITY" "$SIG_PARAMS")

# Sign with Ed25519, base64-encode the raw signature. We materialise
# the signature base to a temp file because LibreSSL (macOS default)
# does not accept `-rawin` from stdin the way OpenSSL does.
TMPBASE=$(mktemp)
TMPSIG=$(mktemp)
trap 'rm -f "$TMPBASE" "$TMPSIG"' EXIT
printf "%s" "$SIG_BASE" > "$TMPBASE"
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$TMPBASE" -out "$TMPSIG"
SIG_B64=$(base64 < "$TMPSIG" | tr -d '\n')
SIGNATURE_LINE="sig1=:$SIG_B64:"

if [ "$RAW" = "1" ]; then
  printf "Signature-Input: %s\n" "$SIG_INPUT_LINE"
  printf "Signature: %s\n" "$SIGNATURE_LINE"
else
  # Shell-escape for safe `eval`.
  printf "SIG_INPUT=%q\n" "$SIG_INPUT_LINE"
  printf "SIG=%q\n" "$SIGNATURE_LINE"
fi

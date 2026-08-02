# Exposed credentials check
*Last modified: 2026-08-01*

![a basic-auth request using a known-leaked password stamped with the exposed-credential-check header on its way upstream](assets/exposed-credentials.gif)

Tag mode lets the backend decide; block mode rejects outright ([config](../examples/exposed-credentials/)).

The `exposed_credentials` policy detects requests carrying a known-leaked password and either tags the upstream request or blocks the request outright. Modeled after Cloudflare's "Exposed Credential Check" header signaling.

## How it works

1. The policy extracts the password segment of `Authorization: Basic <b64>`.
2. It SHA-1 hashes the password and checks the result against a pre-loaded set built from `passwords:`, `sha1_hashes:`, and `sha1_file:`.
3. On a match the policy either:
   - stamps `exposed-credential-check: leaked-password` on the upstream request (`action: tag`, the default), or
   - rejects the request with `403 Forbidden` (`action: block`).

Only `Authorization: Basic` is inspected today. Bearer tokens and JSON form bodies are out of scope.

## Configuration

```yaml
policies:
  - type: exposed_credentials
    action: tag                       # or "block"
    header: exposed-credential-check  # default
    passwords:
      - password
      - password123
      - letmein
    sha1_hashes:
      # SHA-1("hunter2"), uppercase or lowercase both work.
      - F3BBBD66A63D4BF1747940578EC3D0103530E21D
    sha1_file: /etc/sbproxy/leaked-sha1.txt
```

| Field | Default | Description |
|-------|---------|-------------|
| `provider` | `static` | Source of the exposure list. The current provider is `static`. |
| `action` | `tag` | `tag` stamps the configured header on the upstream. `block` returns 403. |
| `header` | `exposed-credential-check` | Header name when `action: tag`. |
| `passwords` | `[]` | Plaintext passwords. Hashed at compile time; the source strings are not retained on the policy. |
| `sha1_hashes` | `[]` | Inline SHA-1 hex hashes. Useful when distributing pre-hashed lists. |
| `sha1_file` | unset | Path to a file with one SHA-1 hex hash per line. Lines starting with `#` are ignored. |

The policy refuses to compile when no list is supplied. Provide at least one of `passwords`, `sha1_hashes`, or `sha1_file`.

## Hash format

The static provider uses **SHA-1 hex, uppercase**. This matches the format that HIBP returns in its [k-anonymity](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/) range queries, so an operator who downloads the public NTLM/SHA-1 dataset can drop it onto disk and point `sha1_file` at it without any preprocessing.

```
$ printf 'password' | openssl dgst -sha1 -hex | tr a-z A-Z
5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
```

Trim surrounding whitespace; comments (`#`) and blank lines are skipped.

## Calling it

The runnable configuration is
[`examples/exposed-credentials/`](../examples/exposed-credentials/): the block
above with `action: tag`, three plaintext passwords, and the SHA-1 of
`hunter2`, in front of an echo upstream. Start it:

```bash
make run CONFIG=examples/exposed-credentials/sb.yml
```

Because the upstream echoes the request back, the tag the proxy stamped is
visible in its response:

```bash
curl -sS -u alice:password -H 'Host: api.local' \
  http://127.0.0.1:8080/get | jq '.headers["exposed-credential-check"]'
# "leaked-password"
```

The plaintext entry and the hash-only entry behave identically, which is the
point of allowing both:

```bash
curl -sS -u alice:hunter2 -H 'Host: api.local' \
  http://127.0.0.1:8080/get | jq '.headers["exposed-credential-check"]'
# "leaked-password"
```

`hunter2` never appears in the config. Only its SHA-1 does, and the match still
lands. A password on no list stamps nothing at all rather than stamping a
negative verdict:

```bash
curl -sS -u 'alice:8sQ%2nT9.zR1@p#X' -H 'Host: api.local' \
  http://127.0.0.1:8080/get | jq '.headers["exposed-credential-check"] // "not present"'
# "not present"
```

That absence is the contract worth building on. An upstream should treat
"header present" as the signal and must not expect a header saying the
credential is clean.

Under `action: tag` every one of these is a `200`; the request is forwarded
either way and the upstream decides. Switch to `action: block` and the same
leaked credential is refused at the edge instead:

```http
HTTP/1.1 403 Forbidden
content-type: application/json

{"error":"credential flagged as exposed"}
```

The body is a single `error` field. There is no `reason`, and no indication of
which list entry matched, deliberately: telling a caller why their password was
rejected would confirm a specific password is on a public breach list.

## What the upstream sees

```
GET /api/me HTTP/1.1
Host: api.example.com
Authorization: Basic YWxpY2U6aHVudGVyMg==
exposed-credential-check: leaked-password
```

The upstream's response is what decides what to do. Common patterns:

- **Step-up auth**: redirect to MFA when the header is present.
- **Page SecOps**: log the user-id alongside the header value.
- **Quietly rotate**: invalidate the credential server-side and force a reset on next login.

Switch `action: block` once those response loops are wired up and the false-positive rate is acceptable.

## Limitations

- Static lists scale to a few million entries before memory becomes a concern.
- SHA-1 is the choice for compatibility with public exposure datasets. It is not a security boundary; the policy assumes the configured list is itself non-sensitive (or stored as hashes).
- The match is exact. We do not normalise (lowercase, NFC, trim) the password before hashing.

## See also

- [configuration.md](configuration.md#exposed_credentials) - schema reference.
- `examples/exposed-credentials/` - runnable example.

# Exposed credentials check
*Last modified: 2026-04-27*

The `exposed_credentials` policy detects requests carrying a known-leaked password and either tags the upstream request or blocks the request outright. Modeled after Cloudflare's "Exposed Credential Check" header signaling.

## How it works

1. The policy extracts the password segment of `Authorization: Basic <b64>`.
2. It SHA-1 hashes the password and checks the result against a pre-loaded set built from `passwords:`, `sha1_hashes:`, and `sha1_file:`.
3. On a match the policy either:
   - stamps `exposed-credential-check: leaked-password` on the upstream request (`action: tag`, the default), or
   - rejects the request with `403 Forbidden` (`action: block`).

Only `Authorization: Basic` is inspected today. Bearer tokens and JSON form bodies are out of scope for the OSS provider; the enterprise build extends to JSON form lookups via the HIBP k-anonymity adapter.

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
| `provider` | `static` | Source of the exposure list. OSS only ships `static`; HIBP lives in the enterprise build. |
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

- Static lists scale to a few million entries before memory becomes a concern. For the full HIBP corpus (1B+ rows), use the enterprise build with the HIBP adapter.
- SHA-1 is the choice for compatibility with public exposure datasets. It is not a security boundary; the policy assumes the configured list is itself non-sensitive (or stored as hashes).
- The match is exact. We do not normalise (lowercase, NFC, trim) the password before hashing.

## See also

- [configuration.md](configuration.md#exposed-credentials) - schema reference.
- `examples/77-exposed-credentials/` - runnable example.

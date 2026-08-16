# DPoP-bound Bearer tokens (RFC 9449)

*Last modified: 2026-08-16*

A stolen Bearer token is only useful if the attacker can also replay it. RFC 9449 (DPoP, "Demonstrating Proof of Possession") binds each token to a key the legitimate client signs with on every request. The proxy reads the `DPoP:` header, verifies the proof, and checks the proof's JWK thumbprint against the operator-stamped `dpop_jkt` metadata on the matched token entry. A bare `Authorization: Bearer` header without a matching proof is rejected with 401 before `test.sbproxy.dev` is contacted.

## Run

```bash
make run CONFIG=examples/auth-bearer-dpop/sb.yml
```

No env vars required.

## Try it

Bearer token alone, no DPoP proof, rejected:

```bash
$ curl -i http://127.0.0.1:8080/anything \
       -H 'Host: api.local' \
       -H 'Authorization: Bearer service-token-1'
HTTP/1.1 401 Unauthorized

{"error":"DPoP verification failed: missing DPoP header"}
```

A DPoP proof is bound to one specific key, so `sb.yml`'s `dpop_jkt` has to be the RFC 7638 thumbprint of whatever key you actually sign with. The shipped `sb.yml` ships a placeholder value (`REPLACE-WITH-YOUR-OWN-JKT-see-README`): nobody has published a private key for it, so no proof can ever match it. Generating a DPoP proof is the client's job; libraries exist for Python, Go, Java, and JavaScript (search for "dpop client library"). The proof's claims must include `htm` (request method), `htu` (request URL), `jti` (unique id), and `iat`; the JWS header carries `typ: "dpop+jwt"` and the JWK of the signing key.

To actually see the 200, generate a throwaway ES256 key, compute its thumbprint the same way the proxy does (RFC 7638 canonical JSON, SHA-256, base64url no padding), and sign a proof for this exact request. This one-off script needs the `cryptography` package (`pip install cryptography`):

```bash
python3 - <<'PY'
import base64, hashlib, json, time, uuid
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes

def b64url(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
def i2b(n): return n.to_bytes(32, "big")

htu, htm = "https://api.local/anything", "GET"
key = ec.generate_private_key(ec.SECP256R1())
pn = key.public_key().public_numbers()
x, y = b64url(i2b(pn.x)), b64url(i2b(pn.y))

canonical = f'{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}'
jkt = b64url(hashlib.sha256(canonical.encode()).digest())

header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": {"kty": "EC", "crv": "P-256", "x": x, "y": y}}
claims = {"jti": str(uuid.uuid4()), "htm": htm, "htu": htu, "iat": int(time.time())}
signing_input = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
    b64url(json.dumps(claims, separators=(",", ":")).encode())
r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
proof = signing_input + "." + b64url(i2b(r) + i2b(s))

print(f"jkt={jkt}")
print(f"proof={proof}")
PY
```

Paste the printed `jkt` into `sb.yml`'s `metadata.dpop_jkt` (the config watcher picks up the change automatically), then use the printed `proof` within the default 60-second `iat` window:

```bash
$ curl -i http://127.0.0.1:8080/anything \
       -H 'Host: api.local' \
       -H 'Authorization: Bearer service-token-1' \
       -H "DPoP: <proof from the script above>"
HTTP/1.1 200 OK
```

Confirmed end to end: with a matching `jkt` and a freshly minted proof, the request is forwarded to `test.sbproxy.dev/anything` and the upstream echoes the `dpop` and `authorization` headers back in its JSON body.

## What this exercises

- `authentication.type: bearer` - opaque token allowlist
- `require_dpop: true` - every request must carry a valid DPoP proof
- `tokens[].metadata.dpop_jkt` - RFC 7638 SHA-256 thumbprint (base64url, no padding) the proof's JWK must hash to

## See also

- [examples/auth-bearer](../auth-bearer) - plain Bearer allowlist without proof-of-possession
- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema

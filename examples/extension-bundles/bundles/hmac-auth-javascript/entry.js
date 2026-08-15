// Self-contained HMAC-SHA256 request authentication hook.
//
// The sbproxy JavaScript sandbox exposes no crypto primitive, so the
// signature check ships inside the bundle: a compact SHA-256 and an
// HMAC wrapper over byte arrays, then a constant-time hex compare. The
// shared secret arrives through the hook's declared `secret_vars`, so
// the operator stores it as a vault or environment reference and the
// plaintext never appears in config.
//
// The client signs `${keyId}.${timestamp}` with the shared secret and
// sends the key id, the timestamp, and the hex signature as headers. A
// valid signature authenticates the request and resolves the key id as
// the subject; anything else is challenged.
//
// Two deliberate choices worth understanding before copying this:
//
//   - The timestamp is signed but not checked for freshness, so a
//     captured (keyId, timestamp, signature) triple replays forever. A
//     production hook should reject a timestamp outside a short window
//     (and, for stricter replay defense, track seen nonces).
//
//   - The two denials are classified differently for trust scoring. A
//     request with no credentials is a neutral `deny_with_headers`
//     challenge (the default classification). A request whose signature
//     failed is a `deny_with_headers` with `denial_kind: "invalid_proof"`
//     and an RFC 6750 `WWW-Authenticate: ... error="invalid_token"`
//     header, so it carries the standard challenge header AND still
//     raises the suspicious-trust tier. Marking a failed credential
//     explicitly is what keeps a brute-force attempt visible; a bare
//     `deny_with_headers` would be scored as a benign challenge.

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

// SHA-256 over a byte array, returning a 32-byte array.
function sha256(bytes) {
  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ];
  const length = bytes.length;
  const bitLen = length * 8;
  // Pad: 0x80, then zeros to 56 mod 64, then 64-bit big-endian length.
  const withOne = length + 1;
  const total = withOne + ((56 - (withOne % 64) + 64) % 64) + 8;
  const msg = new Uint8Array(total);
  msg.set(bytes);
  msg[length] = 0x80;
  // 64-bit length; bitLen fits in 32 bits for the short inputs this hook signs.
  msg[total - 4] = (bitLen >>> 24) & 0xff;
  msg[total - 3] = (bitLen >>> 16) & 0xff;
  msg[total - 2] = (bitLen >>> 8) & 0xff;
  msg[total - 1] = bitLen & 0xff;

  const w = new Array(64);
  for (let offset = 0; offset < total; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] =
        ((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (h[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (h[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (h[i] >>> 8) & 0xff;
    out[i * 4 + 3] = h[i] & 0xff;
  }
  return out;
}

// UTF-8 encode by code point, so an astral character (an emoji, a rare
// script) in a secret or key id is one 4-byte sequence rather than two
// lone-surrogate 3-byte sequences. Iterating with `for..of` and
// `codePointAt` walks whole code points; a `charCodeAt` loop would split
// surrogate pairs and diverge from a reference HMAC over the same string.
function utf8(text) {
  const out = [];
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return new Uint8Array(out);
}

function hmacSha256Hex(secret, message) {
  const blockSize = 64;
  let key = utf8(secret);
  if (key.length > blockSize) {
    key = sha256(key);
  }
  const padded = new Uint8Array(blockSize);
  padded.set(key);
  const inner = new Uint8Array(blockSize);
  const outer = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    inner[i] = padded[i] ^ 0x36;
    outer[i] = padded[i] ^ 0x5c;
  }
  const msgBytes = utf8(message);
  const innerInput = new Uint8Array(blockSize + msgBytes.length);
  innerInput.set(inner);
  innerInput.set(msgBytes, blockSize);
  const innerHash = sha256(innerInput);
  const outerInput = new Uint8Array(blockSize + 32);
  outerInput.set(outer);
  outerInput.set(innerHash, blockSize);
  const digest = sha256(outerInput);
  let hex = "";
  for (let i = 0; i < digest.length; i++) {
    hex += digest[i].toString(16).padStart(2, "0");
  }
  return hex;
}

// Constant-time hex-string comparison: equal length, XOR-accumulate.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function header(headers, name) {
  const wanted = name.toLowerCase();
  const found = headers.find(([key]) => key.toLowerCase() === wanted);
  return found ? found[1] : null;
}

function challenge() {
  return {
    version: "sbproxy-envelope/v1",
    decision: "deny_with_headers",
    status: 401,
    message: "valid request signature required",
    headers: [["WWW-Authenticate", 'HMAC realm="sbproxy"']],
  };
}

export function run(input) {
  const config = input.config;
  const headers = input.request.headers;
  const keyId = header(headers, config.key_header);
  const timestamp = header(headers, config.timestamp_header);
  const signature = header(headers, config.signature_header);

  if (!keyId || !timestamp || !signature) {
    return challenge();
  }

  const expected = hmacSha256Hex(config.signing_secret, `${keyId}.${timestamp}`);
  if (!timingSafeEqual(expected, signature.toLowerCase())) {
    return {
      version: "sbproxy-envelope/v1",
      decision: "deny_with_headers",
      status: 401,
      message: "invalid request signature",
      headers: [["WWW-Authenticate", 'HMAC error="invalid_token"']],
      denial_kind: "invalid_proof",
    };
  }

  return {
    version: "sbproxy-envelope/v1",
    decision: "allow",
    sub: keyId,
    source: "header",
  };
}

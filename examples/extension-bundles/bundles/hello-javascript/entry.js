// The JS sandbox is bare QuickJS plus json_encode / json_decode. There
// is no atob, btoa, Buffer, TextEncoder, or crypto primitive, so a hook
// that needs encoding carries its own. See hmac-auth-javascript for HMAC.

const B64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function utf8Bytes(text) {
  const bytes = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 128) {
      bytes.push(code);
    } else {
      throw new Error("hello-javascript fixture is ASCII-only");
    }
  }
  return bytes;
}

function bytesToUtf8(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i++) {
    text += String.fromCharCode(bytes[i]);
  }
  return text;
}

function bytesToBase64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64[a >> 2];
    out += B64[((a & 3) << 4) | (b >> 4)];
    out += i + 1 < bytes.length ? B64[((b & 15) << 2) | (c >> 6)] : "=";
    out += i + 2 < bytes.length ? B64[c & 63] : "=";
  }
  return out;
}

function base64ToBytes(text) {
  const clean = String(text).replace(/=+$/, "");
  const bytes = [];
  for (let i = 0; i < clean.length; i += 4) {
    const e1 = B64.indexOf(clean[i]);
    const e2 = B64.indexOf(clean[i + 1]);
    const e3 = i + 2 < clean.length ? B64.indexOf(clean[i + 2]) : 0;
    const e4 = i + 3 < clean.length ? B64.indexOf(clean[i + 3]) : 0;
    bytes.push(((e1 << 2) | (e2 >> 4)) & 255);
    if (i + 2 < clean.length) bytes.push(((e2 << 4) | (e3 >> 2)) & 255);
    if (i + 3 < clean.length) bytes.push(((e3 << 6) | e4) & 255);
  }
  return bytes;
}

function encodeText(text) {
  return bytesToBase64(utf8Bytes(text));
}

export function respond(input) {
  return {
    version: "sbproxy-envelope/v1",
    outcome: "response",
    status: 200,
    headers: [
      ["content-type", "text/plain; charset=utf-8"],
      [input.config.response_header, "javascript"],
    ],
    body_base64: encodeText("hello from JavaScript\n"),
  };
}

export function transformResponse(input) {
  bytesToUtf8(base64ToBytes(input.body.body_base64));
  return {
    version: "sbproxy-envelope/v1",
    body_base64: encodeText("hello from a JavaScript transform\n"),
  };
}
